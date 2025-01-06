const std = @import("std");

const MarkSweepGc = @import("gc.zig").MarkSweepGc;

const A = struct {
    num: i16,
    b: *B,
};

const B = struct {
    value: *i32,
};

const C = struct {
    d: *D,
};

const D = struct {
    c: *C,
};

fn gcNewNested(gc: *MarkSweepGc) !*A {
    const a = try gc.create(A);
    a.b = try gc.create(B);
    a.b.value = try gc.create(i32);
    return a;
}

fn gcNewCycle(gc: *MarkSweepGc) !*C {
    const c = try gc.create(C);
    c.d = try gc.create(D);
    c.d.c = c;
    return c;
}

fn gcAlloc(gc: *MarkSweepGc) !void {
    for (0..5) |_| {
        _ = try gc.create(i32);
    }

    _ = try gcNewNested(gc);
    _ = try gcNewCycle(gc);
}

fn gcMain(gc: *MarkSweepGc) !void {
    try gcAlloc(gc);

    _ = try gcNewNested(gc);
    _ = try gcNewCycle(gc);

    const num = try gc.create(i32);
    num.* = 100;

    const num2 = try gc.create(i32);
    num2.* = 100;
}

var global_p1: *i32 = undefined;
var global_p2: *i32 = undefined;

pub fn main() !void {
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .init;
    const allocator = gpa.allocator();
    defer std.debug.assert(gpa.deinit() == .ok);

    const managed_heap = try allocator.alloc(u8, 10000);
    defer allocator.free(managed_heap);

    var gc = MarkSweepGc.init(@frameAddress(), managed_heap, allocator);
    defer gc.deinit();

    global_p1 = try gc.create(i32);
    global_p2 = try gc.create(i32);
    std.debug.print("global_p1 addr: {d}\n", .{@intFromPtr(global_p1)});
    std.debug.print("global_p2 addr: {d}\n", .{@intFromPtr(global_p2)});

    // I need to wrap the main function because @frameAddress on windows is not the first address of the stack frame.
    // Wrapping the main function will allow marking the local variables.
    // https://github.com/ziglang/zig/issues/18662
    try @call(.never_inline, gcMain, .{&gc});

    gc.collect();
}
