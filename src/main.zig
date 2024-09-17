const std = @import("std");
const c = @cImport({@cInclude("unistd.h");});

const argon2 = std.crypto.pwhash.argon2;
const sha2 = std.crypto.hash.sha2;
const hmac = std.crypto.auth.hmac;

// TODO: Put this in a separate file

const Reader = struct {
    ptr: []u8,
    idx: u32,

    fn readN(self: *Reader, n: u32) []u8 {
        const res = self.ptr[self.idx .. self.idx + n];
        self.idx += n;
        return res;
    }

    fn readByte(self: *Reader) u8 {
        const res: u8 = self.ptr[self.idx];
        self.idx += 1;
        return res;
    }

    fn readU16(self: *Reader) u16 {
        const res: u16 = @as(u16, @intCast(self.ptr[self.idx])) 
            | @as(u16, @intCast(self.ptr[self.idx + 1])) << @intCast(8);
        self.idx += 2;
        return res;
    }

    fn readU32(self: *Reader) u32 {
        const res: u32 = @as(u32, @intCast(self.ptr[self.idx])) 
            | @as(u32, @intCast(self.ptr[self.idx + 1])) << @intCast(8) 
            | @as(u32, @intCast(self.ptr[self.idx + 2])) << @intCast(16) 
            | @as(u32, @intCast(self.ptr[self.idx + 3])) << @intCast(24);
        self.idx += 4;
        return res;
    }

    fn readU64(self: *Reader) u64 {
        const res: u64 = @as(u64, @intCast(self.ptr[self.idx])) 
            | @as(u64, @intCast(self.ptr[self.idx + 1])) << @intCast(8) 
            | @as(u64, @intCast(self.ptr[self.idx + 2])) << @intCast(16) 
            | @as(u64, @intCast(self.ptr[self.idx + 3])) << @intCast(24) 
            | @as(u64, @intCast(self.ptr[self.idx + 4])) << @intCast(32) 
            | @as(u64, @intCast(self.ptr[self.idx + 5])) << @intCast(40) 
            | @as(u64, @intCast(self.ptr[self.idx + 6])) << @intCast(48) 
            | @as(u64, @intCast(self.ptr[self.idx + 7])) << @intCast(54);
        self.idx += 8;
        return res;
    }
};

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

const EndOfHeader = [_]u8{ 0x0D, 0x0A, 0x0D, 0x0A };

const Error = error{
    CorruptedSignature,
    CorruptedHeader,
    UnsupportedKDF,
    UnsupportedKDFVersion,
    UnsupportedVersion, 
    InvalidCredentials
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
    headerEnd: ?u32,
    encAlgo: ?[]u8, 
    compAlgo: ?u32, 
    masterSalt: ?[]u8, 
    nonce: ?[]u8, 
    kdfParams: ?KdfParams, 
    customData: ?CustomData 
};

fn parseKdfParams(r: *Reader) Error!KdfParams {
    var kdfParams: ?KdfParams = null;
    const v: u16 = r.readU16();

    if (v != 0x100) {
        return Error.UnsupportedKDFVersion;
    }

    while (true) {
        const kind = r.readByte();

        switch (kind) {
            0x00 => {
                // NOTE: This is safe due to the null check down below. If the second branch
                // gets executed first this check down below is performed and an error is returned.
                return kdfParams.?;
            },
            else => {
                const nameSize = r.readU32();
                const name = r.readN(nameSize);
                const valueSize = r.readU32();

                if (std.mem.eql(u8, name, "$UUID")) {
                    const value = r.readN(valueSize);
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
                                std.debug.assert(valueSize == 8);
                                params.*.rounds = r.readU64(); 
                            } else if (std.mem.eql(u8, name, "S")) {
                                std.debug.assert(valueSize == 8);
                                params.*.salt = r.readN(valueSize);
                            } else {
                                return Error.CorruptedHeader;
                            }
                        },
                        .argon2 => |*params| {
                            if (std.mem.eql(u8, name, "V")) {
                                std.debug.assert(valueSize == 4);
                                params.*.version = r.readU32(); 
                            } else if (std.mem.eql(u8, name, "S")) {
                                params.*.salt = r.readN(valueSize);
                            } else if (std.mem.eql(u8, name, "I")) {
                                params.*.it = r.readU64();
                            } else if (std.mem.eql(u8, name, "M")) {
                                params.*.mem = r.readU64();
                            } else if (std.mem.eql(u8, name, "P")) {
                                params.*.par = r.readU32();
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

fn parseInnerHeader(r: *Reader) void {
    while (true) {
        const kind = r.readByte();
        const size = r.readU32();

        switch (kind) {
            0 => {
                // end of header
                return;
            },
            1 => {
                // inner encryption algorithm, int32
                std.debug.assert(size == 4);
                const innerEncAlgo = r.readU32();
                std.debug.print("{}\n", .{innerEncAlgo});
            },
            2 => {
                // inner encryption, bytes
            },
            3 => {
                // binary content, bytes
            },
        }
    }
}

fn parseHeader(r: *Reader) Error!Header {
    var header: Header = Header{ 
        .headerEnd = null,
        .encAlgo = null, 
        .compAlgo = null, 
        .masterSalt = null, 
        .nonce = null, 
        .kdfParams = null, 
        .customData = null 
    };

    while (true) {
        const id = r.readByte();
        const size: u32 = r.readU32();

        switch (id) {
            0 => {
                std.debug.assert(size == 4);
                const value = r.readN(size);

                if (!std.mem.eql(u8, value, &EndOfHeader)) {
                    return Error.CorruptedHeader;
                }
                
                header.headerEnd = r.idx;
                return header;
            },
            2 => {
                // encryption algorithm, 16 bytes
                std.debug.assert(size == 16);
                header.encAlgo = r.readN(size);
            },
            3 => {
                std.debug.assert(size == 4);
                // compression algorithm uint32, we only use the first byte as this is 0 or 1
                header.compAlgo = r.readU32(); 
            },
            4 => {
                // salt, 32 bytes
                std.debug.assert(size == 32);
                header.masterSalt = r.readN(32);
            },
            7 => {
                // nonce, byte array
                header.nonce = r.readN(size);
            },
            11 => {
                // kdf parameters, dictionary
                header.kdfParams = try parseKdfParams(r);
            },
            12 => {
                // public custom data, dictionary
                // const customData = try parseCustomData(ptr[offset..]);
                // header.customData = customData;
            },
            else => {
                return Error.CorruptedHeader;
            },
        }
    }
}

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const in = std.mem.span(std.os.argv[1]);
    const passwd = std.mem.span(c.getpass("Password: "));

    var hashedPasswd: [32]u8 = undefined;
    sha2.Sha256.hash(passwd, &hashedPasswd, .{});
    // TODO: concat different keys with the order provided in the docs
    var finalPasswd: [32]u8 = undefined;
    sha2.Sha256.hash(&hashedPasswd, &finalPasswd, .{});

    const file = try std.fs.cwd().openFile(in, .{ .mode = .read_write });
    const md = try file.metadata();

    const ptr = try std.posix.mmap(
        null, 
        @intCast(md.size()),
        std.posix.PROT.READ | std.posix.PROT.WRITE,
        .{ .TYPE = .SHARED }, 
        file.handle, 0
    );

    var r = Reader{
        .ptr = ptr,
        .idx = 0
    };

    if (r.readU32() != 0x9aa2d903) {
        return Error.CorruptedSignature;
    }

    if (r.readU32() != 0xb54bfb67) {
        return Error.CorruptedSignature;
    }

    const version = r.readU32();
    // TODO: add proper version checking
    
    std.debug.print("Version: {x}\n", .{version});
    // make a reader for this pointer slice reading
    const header = try parseHeader(&r);

    switch (header.kdfParams.?) {
        .aesKdf => |*params| {
            std.debug.print("aes-kdf params: {}", .{params.*});
        },
        .argon2 => |*params| {
            // 32 byte is the length of the salt
            var derivedKey: [32]u8 = undefined;
            const mode: argon2.Mode = if (!params.*.isHybrid) .argon2d else .argon2id;
            try argon2.kdf(
                allocator,
                &derivedKey,
                &finalPasswd,
                params.*.salt.?,
                .{
                    .t = @intCast(params.*.it.?),
                    // The api expects the memory to be in kibibytes
                    .m = @intCast(params.*.mem.? / 1024),
                    .p = @intCast(params.*.par.?)
                },
                mode
            );

            // The encryption key is somehow 32 bytes as well...
            var encryptionKey: [32]u8 = undefined;
            // The salt is 32 byte long
            const concated = header.masterSalt.?[0..32].* ++ derivedKey;
            sha2.Sha256.hash(&concated, &encryptionKey, .{});

            const hmacConcated = concated ++ [_]u8{0x01};
            var intermediateHash: [64]u8 = undefined;
            sha2.Sha512.hash(&hmacConcated, &intermediateHash, .{});

            const intConcated = [_]u8{0xFF} ** 8 ++ intermediateHash;
            var hmacHashKey: [64]u8 = undefined;
            sha2.Sha512.hash(&intConcated, &hmacHashKey, .{});

            const headerData = r.ptr[0..header.headerEnd.?];

            const headerSha256 = r.readN(32);
            var headerShaActual: [32]u8 = undefined;
            sha2.Sha256.hash(headerData, &headerShaActual, .{});

            if (!std.mem.eql(u8, headerSha256, &headerShaActual)) {
                return Error.CorruptedHeader;
            }

            const headerHmac256 = r.readN(32);
            var headerHmacActual: [32]u8 = undefined;
            hmac.sha2.HmacSha256.create(&headerHmacActual, headerData, &hmacHashKey);

            if (!std.mem.eql(u8, headerHmac256, &headerHmacActual)) {
                return Error.InvalidCredentials;
            }
            std.debug.print("successfully parsed the header\n", .{});
        }
    }
}

test "simple test" {}
