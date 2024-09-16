const std = @import("std");

const Error = error{
    CorruptedSignature,
    CorruptedHeader,
};

const AESKdfParams = struct { uuid: ?[]u8, s: ?[]u8, r: ?u64 };
const CustomData = struct {};
const Header = struct { encAlgo: ?[]u8, compAlgo: ?u32, salt: ?[]u8, nonce: ?[]u8, kdfParams: ?AESKdfParams, customData: ?CustomData };

fn byteSliceToU64(ptr: []u8) u64 {
    const res: u64 = @as(u64, @intCast(ptr[0])) | @as(u64, @intCast(ptr[1])) << @intCast(8) | @as(u64, @intCast(ptr[2])) << @intCast(16) | @as(u64, @intCast(ptr[3])) << @intCast(24) | @as(u64, @intCast(ptr[4])) << @intCast(32) | @as(u64, @intCast(ptr[5])) << @intCast(40) | @as(u64, @intCast(ptr[6])) << @intCast(48) | @as(u64, @intCast(ptr[7])) << @intCast(54);

    return res;
}

fn byteSliceToU32(ptr: []u8) u32 {
    const res: u32 = @as(u32, @intCast(ptr[0])) | @as(u32, @intCast(ptr[1])) << @intCast(8) | @as(u32, @intCast(ptr[2])) << @intCast(16) | @as(u32, @intCast(ptr[3])) << @intCast(24);

    return res;
}

fn byteSliceToU16(ptr: []u8) u16 {
    const res: u16 = @as(u16, @intCast(ptr[0])) | @as(u16, @intCast(ptr[1])) << @intCast(8);
    return res;
}

fn parseKdfParams(ptr: []u8) Error!AESKdfParams {
    var kdfParams = AESKdfParams{ .uuid = null, .s = null, .r = null };
    var offset: usize = 0;
    const v: u16 = byteSliceToU16(ptr[0..2]);
    offset += 2;
    std.debug.print("version: {x}\n", .{v});

    while (true) {
        const kind = ptr[offset];
        offset += 1;

        switch (kind) {
            0x00 => {
                return kdfParams;
            },
            else => {
                const nameSize = byteSliceToU32(ptr[offset .. offset + 4]);
                offset += 4;
                const name = ptr[offset .. offset + nameSize];
                offset += nameSize;
                const valueSize = byteSliceToU32(ptr[offset .. offset + 4]);
                offset += 4;
                const value = ptr[offset .. offset + valueSize];
                offset += valueSize;

                if (std.mem.eql(u8, name, "$UUID")) {
                    kdfParams.uuid = value;
                } else if (std.mem.eql(u8, name, "R")) {
                    kdfParams.r = byteSliceToU64(value);
                } else if (std.mem.eql(u8, name, "S")) {
                    kdfParams.s = value;
                } else {
                    return Error.CorruptedHeader;
                }
            },
        }
    }

    return Error.CorruptedHeader;
}

fn parseCustomData(ptr: []u8) Error!CustomData {
    const v: u16 = byteSliceToU16(ptr[0..2]);
    std.debug.print("version: {x}", .{v});

    return Error.CorruptedHeader;
}

fn parseHeader(ptr: []u8) Error!Header {
    var header: Header = Header{ .encAlgo = null, .compAlgo = null, .salt = null, .nonce = null, .kdfParams = null, .customData = null };
    var offset: usize = 0;

    while (true) {
        const id = ptr[offset];
        offset += 1;

        // TODO: move constant values into constant assignments
        const size: u32 = byteSliceToU32(ptr[offset .. offset + 4]);
        offset += 4;

        switch (id) {
            0 => {
                return header;
            },
            2 => {
                // encryption algorithm, 16 bytes
                std.debug.assert(size == 16);
                const encAlgo = ptr[offset .. offset + size];
                header.encAlgo = encAlgo;
            },
            3 => {
                // compression algorithm uint32, we only use the first byte as this is 0 or 1
                std.debug.assert(size == 4);
                const compAlgo = ptr[offset];
                header.compAlgo = compAlgo;
            },
            4 => {
                // salt, 32 bytes
                std.debug.assert(size == 32);
                const salt = ptr[offset .. offset + size];
                header.salt = salt;
            },
            7 => {
                // nonce, byte array
                const nonce = ptr[offset .. offset + size];
                header.nonce = nonce;
            },
            11 => {
                // kdf parameters, dictionary
                const kdfParams = try parseKdfParams(ptr[offset..]);
                header.kdfParams = kdfParams;
            },
            12 => {
                // public custom data, dictionary
                const customData = try parseCustomData(ptr[offset..]);
                header.customData = customData;
            },
            else => {
                return Error.CorruptedHeader;
            },
        }

        offset += size;
    }
}

pub fn main() !void {
    const in = std.mem.span(std.os.argv[1]);
    const file = try std.fs.cwd().openFile(in, .{ .mode = .read_write });
    const md = try file.metadata();

    const ptr = try std.posix.mmap(null, @intCast(md.size()), std.posix.PROT.READ | std.posix.PROT.WRITE, .{ .TYPE = .SHARED }, file.handle, 0);
    const sig: [*]u32 = @ptrCast(ptr[0..12]);

    if (sig[0] != 0x9aa2d903) {
        return Error.CorruptedSignature;
    }

    if (sig[1] != 0xb54bfb67) {
        return Error.CorruptedSignature;
    }

    const version = sig[2];
    std.debug.print("Version: {x}\n", .{version});

    const header = try parseHeader(ptr[12..]);
    std.debug.print("header: {}", .{header});
}

test "simple test" {}
