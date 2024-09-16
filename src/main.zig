const std = @import("std");

// TODO: Put this in a separate file

const AES256 = [_]u8{ 
    0x31, 0xC1, 0xF2, 0xE6, 0xBF, 0x71, 0x43, 0x50, 0xBE, 0x58, 0x05, 0x21, 0x6A, 0xFC, 0x5A, 0xF 
};

const ChaCha2 = [_]u8{
    0xD6, 0x03, 0x8A, 0x2B, 0x8B, 0x6F, 0x4C, 0xB5, 0xA5, 0x24, 0x33, 0x9A, 0x31, 0xDB, 0xB5, 0x9A
};

const AESKDF = [_]u8{
    0xC9, 0xD9, 0xF3, 0x9A, 0x62, 0x8A, 0x44, 0x60, 0xBF, 0x74, 0x0D, 0x08, 0xC1, 0x8A, 0x4F, 0xEA
};

const Argon2d = [_]u8{
    0xEF, 0x63, 0x6D, 0xDF, 0x8C, 0x29, 0x44, 0x4B, 0x91, 0xF7, 0xA9, 0xA4, 0x03, 0xE3, 0x0A, 0x0C
};

const Argon2id = [_]u8{
    0x9E, 0x29, 0x8B, 0x19, 0x56, 0xDB, 0x47, 0x73, 0xB2, 0x3D, 0xFC, 0x3E, 0xC6, 0xF0, 0xA1, 0xE6
};

const Error = error{
    CorruptedSignature,
    CorruptedHeader,
    UnsupportedKDF,
    UnsupportedKDFVersion,
    UnsupportedVersion
};

const AESKdfParams = struct { 
    salt: ?[]u8, 
    rounds: ?u64 
};

const Argon2Params = struct { 
    isHybrid: bool,
    version: ?u32,
    salt: ?[]u8,
    it: ?u64,
    mem: ?u64,
    par: ?u32
};

const KdfParams = union(enum) {
    aesKdf: AESKdfParams,
    argon2: Argon2Params,
};

const CustomData = struct {};
const Header = struct { 
    encAlgo: ?[]u8, 
    compAlgo: ?u32, 
    salt: ?[]u8, 
    nonce: ?[]u8, 
    kdfParams: ?KdfParams, 
    customData: ?CustomData 
};

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

fn parseKdfParams(ptr: []u8) Error!KdfParams {
    var kdfParams: ?KdfParams = null;
    var offset: usize = 0;
    const v: u16 = byteSliceToU16(ptr[0..2]);
    offset += 2;

    if (v != 0x100) {
        return Error.UnsupportedKDFVersion;
    }

    while (true) {
        const kind = ptr[offset];
        offset += 1;

        switch (kind) {
            0x00 => {
                // NOTE: This is safe due to the null check down below. If the second branch
                // gets executed first this check down below is performed and an error is returned.
                return kdfParams.?;
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
                    if (std.mem.eql(u8, value, &AESKDF)) {
                        kdfParams = KdfParams{ 
                            .aesKdf = AESKdfParams{
                                .salt = null,
                                .rounds = null
                            }
                        };
                    } else if (std.mem.eql(u8, value, &Argon2d) or std.mem.eql(u8, value, &Argon2id)) {
                        kdfParams = KdfParams{ 
                            .argon2 = Argon2Params{ 
                                .isHybrid = std.mem.eql(u8, value, &Argon2id),
                                .version = null,
                                .salt = null,
                                .it = null,
                                .mem = null,
                                .par = null,
                            }
                        };
                    } else {
                        return Error.UnsupportedKDF;
                    }
                } else {
                    if (kdfParams == null) {
                        return Error.CorruptedHeader;
                    }

                    switch (kdfParams.?) {
                        .aesKdf => |*params| {
                            if (std.mem.eql(u8, name, "R")) {
                                params.*.rounds = byteSliceToU64(value);
                            } else if (std.mem.eql(u8, name, "S")) {
                                params.*.salt = value;
                            } else {
                                return Error.CorruptedHeader;
                            }
                        },
                        .argon2 => |*params| {
                            if (std.mem.eql(u8, name, "V")) {
                                params.*.version = byteSliceToU32(value);
                            } else if (std.mem.eql(u8, name, "S")) {
                                params.*.salt = value;
                            } else if (std.mem.eql(u8, name, "I")) {
                                params.*.it = byteSliceToU64(value);
                            } else if (std.mem.eql(u8, name, "M")) {
                                params.*.mem = byteSliceToU64(value);
                            } else if (std.mem.eql(u8, name, "P")) {
                                params.*.par = byteSliceToU32(value);
                            } else {
                                return Error.CorruptedHeader;
                            }
                        }
                    }
                }
            },
        }
    }

    return Error.CorruptedHeader;
}

fn parseCustomData(_: []u8) Error!CustomData {
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

    // TODO: add proper version checking
    std.debug.print("Version: {x}\n", .{version});

    const header = try parseHeader(ptr[12..]);

    switch (header.kdfParams.?) {
        .aesKdf => |*params| {
            std.debug.print("aes-kdf params: {}", .{params.*});
        },
        .argon2 => |*params| {
            std.crypto.argon2.kdf();
            std.debug.print("argon params: {}", .{params.*});
        }
    }

    std.debug.print("header: {}\n", .{header});
}

test "simple test" {}
