const std = @import("std");

const sha2 = std.crypto.hash.sha2;
const hmac = std.crypto.auth.hmac;
const aes = std.crypto.core.aes;

const cbc_decrypt = @import("cbc_decrypt.zig");
const uuid = @import("uuid.zig");

const err = @import("error.zig");
const Error = err.Error;

const kdf = @import("kdf.zig");
const KdfParams = kdf.KdfParams;
const AesKdfParams = kdf.AesKdfParams;
const Argon2Params = kdf.Argon2Params;

const endOfHeader = [_]u8{ 0x0D, 0x0A, 0x0D, 0x0A };

pub const Reader = struct {
    ptr: []u8,
    idx: u32,

    pub fn init(ptr: []u8) Reader {
        return Reader{
            .ptr = ptr,
            .idx = 0
        };
    }

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

    // TODO: Probably this reading interface is very inefficient...
    
    fn readU16(self: *Reader, v: *u16) []u8 {
        v.* = @as(u16, @intCast(self.ptr[self.idx])) 
            | @as(u16, @intCast(self.ptr[self.idx + 1])) << @intCast(8);

        const res = self.ptr[self.idx .. self.idx + 2];
        self.idx += 2;
        return res;
    }

    fn readU32(self: *Reader, v: *u32) []u8 {
        v.* = @as(u32, @intCast(self.ptr[self.idx])) 
            | @as(u32, @intCast(self.ptr[self.idx + 1])) << @intCast(8) 
            | @as(u32, @intCast(self.ptr[self.idx + 2])) << @intCast(16) 
            | @as(u32, @intCast(self.ptr[self.idx + 3])) << @intCast(24);

        const res = self.ptr[self.idx .. self.idx + 4];
        self.idx += 4;
        return res;
    }

    fn readU64(self: *Reader, v: *u64) []u8 {
        v.* = @as(u64, @intCast(self.ptr[self.idx])) 
            | @as(u64, @intCast(self.ptr[self.idx + 1])) << @intCast(8) 
            | @as(u64, @intCast(self.ptr[self.idx + 2])) << @intCast(16) 
            | @as(u64, @intCast(self.ptr[self.idx + 3])) << @intCast(24) 
            | @as(u64, @intCast(self.ptr[self.idx + 4])) << @intCast(32) 
            | @as(u64, @intCast(self.ptr[self.idx + 5])) << @intCast(40) 
            | @as(u64, @intCast(self.ptr[self.idx + 6])) << @intCast(48) 
            | @as(u64, @intCast(self.ptr[self.idx + 7])) << @intCast(54);

        const res = self.ptr[self.idx .. self.idx + 8];
        self.idx += 8;
        return res;
    }
};



const CustomData = struct {};
const Header = struct { 
    encAlgo: ?[]u8, 
    compAlgo: ?u32, 
    masterSalt: ?[]u8, 
    nonce: ?[]u8, 
    kdfParams: ?KdfParams, 
    customData: ?CustomData 
};

fn copyFront(dest: []u8, source: []const u8) void {
    std.debug.assert(dest.len >= source.len);

    for (0..source.len) |i| {
        dest[i] = source[i];
    }
}


fn copyBack(dest: []u8, source: []const u8) void {
    std.debug.assert(dest.len >= source.len);

    var destI = dest.len;
    var sourceI = source.len;

    while (sourceI > 0) {
        sourceI -= 1;
        destI -= 1;

        dest[destI] = source[sourceI];
    }
}

fn parseKdfParams(r: *Reader) Error!KdfParams {
    var kdfParams: ?KdfParams = null;
    var v: u16 = undefined;
    _ = r.readU16(&v);

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
                var nameSize: u32 = undefined; 
                _ = r.readU32(&nameSize);
                const name = r.readN(nameSize);
                var valueSize: u32 = undefined;
                _ = r.readU32(&valueSize);

                if (std.mem.eql(u8, name, "$UUID")) {
                    const value = r.readN(valueSize);
                    if (std.mem.eql(u8, value, &uuid.aes256)) {
                        kdfParams = KdfParams{ 
                            .aesKdf = AesKdfParams{
                                .salt = null,
                                .rounds = null
                            }
                        };
                    } else if (std.mem.eql(u8, value, &uuid.argon2d) or std.mem.eql(u8, value, &uuid.argon2id)) {
                        kdfParams = KdfParams{ 
                            .argon2 = Argon2Params{ 
                                .isHybrid = std.mem.eql(u8, value, &uuid.argon2id),
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
                                params.*.rounds = undefined;
                                _ = r.readU64(&params.*.rounds.?); 
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
                                params.*.version = undefined;
                                _ = r.readU32(&params.*.version.?); 
                            } else if (std.mem.eql(u8, name, "S")) {
                                params.*.salt = r.readN(valueSize);
                            } else if (std.mem.eql(u8, name, "I")) {
                                params.*.it = undefined;
                                _ = r.readU64(&params.*.it.?);
                            } else if (std.mem.eql(u8, name, "M")) {
                                params.*.mem = undefined;
                                _ = r.readU64(&params.*.mem.?);
                            } else if (std.mem.eql(u8, name, "P")) {
                                params.*.par = undefined;
                                _ = r.readU32(&params.*.par.?);
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
        var size: u32 = undefined;
        _ = r.readU32(&size);

        switch (kind) {
            0 => {
                // end of header
                return;
            },
            1 => {
                // inner encryption algorithm, int32
                std.debug.assert(size == 4);
                var innerEncAlgo: u32 = undefined;
                _ = r.readU32(&innerEncAlgo);
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
        .encAlgo = null, 
        .compAlgo = null, 
        .masterSalt = null, 
        .nonce = null, 
        .kdfParams = null, 
        .customData = null 
    };

    while (true) {
        const id = r.readByte();
        var size: u32 = undefined;
        _ = r.readU32(&size);

        switch (id) {
            0 => {
                std.debug.assert(size == 4);
                const value = r.readN(size);

                if (!std.mem.eql(u8, value, &endOfHeader)) {
                    return Error.CorruptedHeader;
                }
                
                return header;
            },
            2 => {
                // encryption algorithm, 16 bytes
                std.debug.assert(size == 16);
                header.encAlgo = r.readN(size);
            },
            3 => {
                // compression algorithm uint32, we only use the first byte as this is 0 or 1
                std.debug.assert(size == 4);
                header.compAlgo = undefined;
                _ = r.readU32(&header.compAlgo.?); 
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

pub fn read_kdbx(
    allocator: std.mem.Allocator, 
    r: *Reader,
    finalPasswd: []u8
) Error!void {
    var sig1: u32 = undefined;
    _ = r.readU32(&sig1);
    if (sig1 != 0x9aa2d903) {
        return Error.CorruptedSignature;
    }

    var sig2: u32 = undefined;
    _ = r.readU32(&sig2);
    if (sig2 != 0xb54bfb67) {
        return Error.CorruptedSignature;
    }

    var version: u32 = undefined;
    _ = r.readU32(&version);
    // TODO: add proper version checking
    
    std.debug.print("Version: {x}\n", .{version});
    // make a reader for this pointer slice reading
    const header = try parseHeader(r);


    // TODO: Clean up this mess
    
    var derivedKey: [32]u8 = undefined;

    try kdf.deriveKey(
        allocator, 
        header.kdfParams.?, 
        finalPasswd, 
        &derivedKey
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

    const headerData = r.ptr[0..r.idx];

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

    const blockIdx = [_]u8{ 0x00 } ** 8;
    const blockHmac = r.readN(32);
    var dataSize: u32 = undefined;
    const p = r.readU32(&dataSize);
    const m = r.readN(dataSize);

    const block = allocator.alloc(u8, 8 + 4 + m.len) catch return Error.OutOfMemory;
    @memcpy(block[0..12], blockIdx ++ p[0..4]);
    @memcpy(block[block.len - m.len .. block.len], m);

    var blockKey: [64]u8 = undefined;
    const blockHmacConcated = [_]u8{ 0x00 } ** 8 ++ intermediateHash;
    sha2.Sha512.hash(&blockHmacConcated, &blockKey, .{});

    var blockHmacActual: [32]u8 = undefined;
    hmac.sha2.HmacSha256.create(&blockHmacActual, block, &blockKey);
     
    if (!std.mem.eql(u8, blockHmac, &blockHmacActual)) {
        return Error.CorruptedBlock;
    }


    // TODO: implement cipher block chaining mode...
    //
    const decrypted: []u8 = try allocator.alloc(u8, dataSize);

    cbc_decrypt.cbc_aes256(
        &encryptionKey,
        header.nonce.?[0..16],
        decrypted,
        m
    );

    std.debug.print("decrypted block: {x}\n", .{decrypted});
    const f = std.fs.cwd().createFile("decrypted", .{}) catch return;
    _ = f.write(decrypted) catch return;

    // var decrypted: [16]u8 = undefined;
}
