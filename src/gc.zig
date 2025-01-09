const builtin = @import("builtin");
const std = @import("std");
const win32 = @import("win32.zig");

pub const MarkSweepGc = struct {
    stack_start: usize,
    data_region: []u8,
    bss_region: []u8,
    allocator: std.mem.Allocator,
    mark_list_allocator: std.mem.Allocator,
    mark_list: std.MultiArrayList(HeapObject),

    // debug
    alloc_count: usize = 0,
    dealloc_count: usize = 0,

    const HeapObject = struct {
        marked: bool = false, // maybe use tagged pointer?
        alignment: u8,
        size: usize,
        ptr: usize,
    };

    pub inline fn init(stack_start: usize, allocator: std.mem.Allocator, mark_list_allocator: std.mem.Allocator) @This() {
        var data_region: []u8 = &.{};
        var bss_region: []u8 = &.{};

        switch (builtin.os.tag) {
            .windows => {
                const h_module = win32.GetModuleHandleA(null);
                const dos_header: *win32.IMAGE_DOS_HEADER = @ptrCast(@alignCast(h_module));
                const nt_headers: *win32.IMAGE_NT_HEADERS = @ptrFromInt(@intFromPtr(h_module) + @as(usize, @intCast(dos_header.e_lfanew)));

                var section_name_data = [_]u8{0} ** 8;
                var section_name_bss = [_]u8{0} ** 8;
                @memcpy(@as([*]u8, &section_name_data), ".data");
                @memcpy(@as([*]u8, &section_name_bss), ".bss");

                const first_section_header: *win32.IMAGE_SECTION_HEADER = @ptrFromInt(@intFromPtr(nt_headers) + @sizeOf(win32.IMAGE_NT_HEADERS));
                const section_headers = @as([*]win32.IMAGE_SECTION_HEADER, @ptrCast(first_section_header))[0..nt_headers.FileHeader.NumberOfSections];
                for (section_headers) |section_header| {
                    if (std.mem.eql(u8, &section_header.Name, &section_name_data)) {
                        const start_addr = @intFromPtr(h_module) + section_header.VirtualAddress;
                        data_region = @as([*]u8, @ptrFromInt(start_addr))[0..section_header.VirtualSize];
                        data_region = data_region[@intFromPtr(data_region.ptr) % @sizeOf(usize) ..];
                    }
                    if (std.mem.eql(u8, &section_header.Name, &section_name_bss)) {
                        const start_addr = @intFromPtr(h_module) + section_header.VirtualAddress;
                        bss_region = @as([*]u8, @ptrFromInt(start_addr))[0..section_header.VirtualSize];
                        bss_region = bss_region[@intFromPtr(bss_region.ptr) % @sizeOf(usize) ..];
                    }
                }
            },
            else => {
                @panic(std.fmt.comptimePrint("MarkSweepGc is not implemented for \"{s}\"\n", .{@tagName(builtin.os.tag)}));
            },
        }

        return .{
            .stack_start = stack_start,
            .data_region = data_region,
            .bss_region = bss_region,
            .allocator = allocator,
            .mark_list_allocator = mark_list_allocator,
            .mark_list = .{},
        };
    }

    pub fn deinit(self: *@This()) void {
        self.mark_list.deinit(self.mark_list_allocator);
    }

    fn mark(self: *@This(), region: []u8) void {
        const mark_list = self.mark_list.slice();

        var iter = std.mem.window(u8, region, @sizeOf(usize), @sizeOf(usize));
        while (iter.next()) |slice| {
            const value = std.mem.bytesToValue(usize, slice);
            // std.debug.print("{d}: {d}\n", .{@intFromPtr(slice.ptr), value});

            if (std.mem.indexOfScalar(usize, mark_list.items(.ptr), value)) |i| {
                if (!mark_list.items(.marked)[i]) {
                    // std.debug.print("mark object: {d}\n", .{value});
                    mark_list.items(.marked)[i] = true;
                    if (mark_list.items(.size)[i] >= @sizeOf(usize)) {
                        // traverse nested pointer
                        self.mark(@as([*]u8, @ptrFromInt(value))[0..mark_list.items(.size)[i]]);
                    }
                }
            }
        }
    }

    fn sweep(self: *@This()) void {
        const mark_list = self.mark_list.slice();

        var i: usize = 0;
        while (i < self.mark_list.len) {
            if (mark_list.items(.marked)[i]) {
                // std.debug.print("found marked pointer: {d}\n", .{mark_list.items(.ptr)[i]});
                mark_list.items(.marked)[i] = false;
                i += 1;
            } else {
                // std.debug.print("deallocate pointer: {d}\n", .{mark_list.items(.ptr)[i]});

                // deallocate memory
                const buf = @as([*]u8, @ptrFromInt(mark_list.items(.ptr)[i]))[0..mark_list.items(.size)[i]];
                self.allocator.rawFree(buf, std.math.log2(mark_list.items(.alignment)[i]), @returnAddress());

                // remove from make_list
                _ = self.mark_list.swapRemove(i);

                self.dealloc_count += 1;
            }
        }
    }

    inline fn registerToStack() void {
        // store registers value to local variable
        const rax: usize = asm volatile (""
            : [_] "={rax}" (-> usize),
        );
        _ = rax;
        const rcx: usize = asm volatile (""
            : [_] "={rcx}" (-> usize),
        );
        _ = rcx;
        const rdx: usize = asm volatile (""
            : [_] "={rdx}" (-> usize),
        );
        _ = rdx;
        const rbx: usize = asm volatile (""
            : [_] "={rbx}" (-> usize),
        );
        _ = rbx;
        const rsi: usize = asm volatile (""
            : [_] "={rsi}" (-> usize),
        );
        _ = rsi;
        const rdi: usize = asm volatile (""
            : [_] "={rdi}" (-> usize),
        );
        _ = rdi;
    }

    fn collectNoInline(self: *@This()) void {
        var stack_region = blk: {
            const stack_end = @frameAddress();
            if (self.stack_start > stack_end) {
                const len = self.stack_start - stack_end;
                break :blk @as([*]u8, @ptrFromInt(stack_end))[0..len];
            } else {
                const len = stack_end - self.stack_start;
                break :blk @as([*]u8, @ptrFromInt(self.stack_start))[0..len];
            }
        };
        stack_region = stack_region[@intFromPtr(stack_region.ptr) % @sizeOf(usize) ..];

        // mark
        self.mark(stack_region);
        if (self.data_region.len != 0) self.mark(self.data_region);
        if (self.bss_region.len != 0) self.mark(self.bss_region);

        // sweep
        self.sweep();
    }

    pub fn collect(self: *@This()) void {
        registerToStack(); // put register values on the stack
        @call(.never_inline, collectNoInline, .{self});

        std.debug.print("gc alloc count: {d}\n", .{self.alloc_count});
        std.debug.print("gc dealloc count: {d}\n", .{self.dealloc_count});
    }

    pub fn create(self: *@This(), comptime T: type) !*T {
        const alignment = @alignOf(T);
        const size = @sizeOf(T);
        const ptr = try self.allocator.alignedAlloc(u8, alignment, size);
        errdefer self.allocator.rawFree(@as([*]u8, @ptrCast(ptr))[0..size], std.math.log2(alignment), @returnAddress());

        try self.mark_list.append(self.mark_list_allocator, .{
            .alignment = alignment,
            .size = size,
            .ptr = @intFromPtr(ptr.ptr),
        });

        self.alloc_count += 1;

        // std.debug.print("gc create {d}\n", .{@intFromPtr(&obj.data)});
        return @ptrCast(ptr);
    }
};
