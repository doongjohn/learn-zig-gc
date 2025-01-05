// https://github.com/howmp/zigshellcode/blob/main/src/win32.zig

const std = @import("std");
const windows = std.os.windows;

pub const IMAGE_DOS_HEADER = extern struct {
    e_magic: windows.WORD,
    e_cblp: windows.WORD,
    e_cp: windows.WORD,
    e_crlc: windows.WORD,
    e_cparhdr: windows.WORD,
    e_minalloc: windows.WORD,
    e_maxalloc: windows.WORD,
    e_ss: windows.WORD,
    e_sp: windows.WORD,
    e_csum: windows.WORD,
    e_ip: windows.WORD,
    e_cs: windows.WORD,
    e_lfarlc: windows.WORD,
    e_ovno: windows.WORD,
    e_res: [4]windows.WORD,
    e_oemid: windows.WORD,
    e_oeminfo: windows.WORD,
    e_res2: [10]windows.WORD,
    e_lfanew: windows.LONG,
};

pub const IMAGE_DATA_DIRECTORY = extern struct {
    VirtualAddress: windows.DWORD,
    Size: windows.DWORD,
};
pub const IMAGE_OPTIONAL_HEADER32 = extern struct {
    Magic: windows.WORD,
    MajorLinkerVersion: windows.BYTE,
    MinorLinkerVersion: windows.BYTE,
    SizeOfCode: windows.DWORD,
    SizeOfInitializedData: windows.DWORD,
    SizeOfUninitializedData: windows.DWORD,
    AddressOfEntryPoint: windows.DWORD,
    BaseOfCode: windows.DWORD,
    BaseOfData: windows.DWORD,
    ImageBase: windows.DWORD,
    SectionAlignment: windows.DWORD,
    FileAlignment: windows.DWORD,
    MajorOperatingSystemVersion: windows.WORD,
    MinorOperatingSystemVersion: windows.WORD,
    MajorImageVersion: windows.WORD,
    MinorImageVersion: windows.WORD,
    MajorSubsystemVersion: windows.WORD,
    MinorSubsystemVersion: windows.WORD,
    Win32VersionValue: windows.DWORD,
    SizeOfImage: windows.DWORD,
    SizeOfHeaders: windows.DWORD,
    CheckSum: windows.DWORD,
    Subsystem: windows.WORD,
    DllCharacteristics: windows.WORD,
    SizeOfStackReserve: windows.DWORD,
    SizeOfStackCommit: windows.DWORD,
    SizeOfHeapReserve: windows.DWORD,
    SizeOfHeapCommit: windows.DWORD,
    LoaderFlags: windows.DWORD,
    NumberOfRvaAndSizes: windows.DWORD,
    DataDirectory: [16]IMAGE_DATA_DIRECTORY,
};
pub const IMAGE_OPTIONAL_HEADER64 = extern struct {
    Magic: windows.WORD,
    MajorLinkerVersion: windows.BYTE,
    MinorLinkerVersion: windows.BYTE,
    SizeOfCode: windows.DWORD,
    SizeOfInitializedData: windows.DWORD,
    SizeOfUninitializedData: windows.DWORD,
    AddressOfEntryPoint: windows.DWORD,
    BaseOfCode: windows.DWORD,
    ImageBase: windows.ULONGLONG,
    SectionAlignment: windows.DWORD,
    FileAlignment: windows.DWORD,
    MajorOperatingSystemVersion: windows.WORD,
    MinorOperatingSystemVersion: windows.WORD,
    MajorImageVersion: windows.WORD,
    MinorImageVersion: windows.WORD,
    MajorSubsystemVersion: windows.WORD,
    MinorSubsystemVersion: windows.WORD,
    Win32VersionValue: windows.DWORD,
    SizeOfImage: windows.DWORD,
    SizeOfHeaders: windows.DWORD,
    CheckSum: windows.DWORD,
    Subsystem: windows.WORD,
    DllCharacteristics: windows.WORD,
    SizeOfStackReserve: windows.ULONGLONG,
    SizeOfStackCommit: windows.ULONGLONG,
    SizeOfHeapReserve: windows.ULONGLONG,
    SizeOfHeapCommit: windows.ULONGLONG,
    LoaderFlags: windows.DWORD,
    NumberOfRvaAndSizes: windows.DWORD,
    DataDirectory: [16]IMAGE_DATA_DIRECTORY,
};
pub const IMAGE_FILE_HEADER = extern struct {
    Machine: windows.WORD,
    NumberOfSections: windows.WORD,
    TimeDateStamp: windows.DWORD,
    PointerToSymbolTable: windows.DWORD,
    NumberOfSymbols: windows.DWORD,
    SizeOfOptionalHeader: windows.WORD,
    Characteristics: windows.WORD,
};
pub const IMAGE_NT_HEADERS64 = extern struct {
    Signature: windows.DWORD,
    FileHeader: IMAGE_FILE_HEADER,
    OptionalHeader: IMAGE_OPTIONAL_HEADER64,
};

pub const IMAGE_NT_HEADERS32 = extern struct {
    Signature: windows.DWORD,
    FileHeader: IMAGE_FILE_HEADER,
    OptionalHeader: IMAGE_OPTIONAL_HEADER32,
};

pub const IMAGE_OPTIONAL_HEADER = if (@sizeOf(usize) == 4) IMAGE_OPTIONAL_HEADER32 else IMAGE_OPTIONAL_HEADER64;
pub const IMAGE_NT_HEADERS = if (@sizeOf(usize) == 4) IMAGE_NT_HEADERS32 else IMAGE_NT_HEADERS64;

pub const IMAGE_SECTION_HEADER = extern struct {
    Name: [8]windows.UCHAR,
    VirtualSize: windows.ULONG,
    VirtualAddress: windows.ULONG,
    SizeOfRawData: windows.ULONG,
    PointerToRawData: windows.ULONG,
    PointerToRelocations: windows.ULONG,
    PointerToLinenumbers: windows.ULONG,
    NumberOfRelocations: windows.USHORT,
    NumberOfLinenumbers: windows.USHORT,
    Characteristics: windows.ULONG,
};

pub extern "kernel32" fn GetModuleHandleA(lpModuleName: ?windows.LPCSTR) callconv(.winapi) windows.HMODULE;
