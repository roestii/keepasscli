// TODO: Migrate the code to use a fixed buffer stream
const std = @import("std");

const sha2 = std.crypto.hash.sha2;
const hmac = std.crypto.auth.hmac;
const aes = std.crypto.core.aes;
const gzip = std.compress.gzip;

const cbc_decrypt = @import("cbc_decrypt.zig");
const uuid = @import("uuid.zig");
const err = @import("error.zig");
const Error = err.Error;

const kdf = @import("kdf.zig");
const KdfParams = kdf.KdfParams;
const AesKdfParams = kdf.AesKdfParams;
const Argon2Params = kdf.Argon2Params;

const endOfHeader = [_]u8{ 0x0D, 0x0A, 0x0D, 0x0A };

fn intToBytes(comptime T: type, v: T) [@divExact(@typeInfo(T).Int.bits, 8)]u8 {
    const n = comptime @divExact(@typeInfo(T).Int.bits, 8);
    var out: [n]u8 = undefined;
    for (0..n) |i| {
        out[i] = @intCast((v >> @intCast(i * 8)) & 0xFF);
    }

    return out;
}

const Compression = enum(u32) { gzip = 1, none = 0 };

pub const Reader = struct {
    ptr: []u8,
    idx: u32,

    pub fn init(ptr: []u8) Reader {
        return Reader{ .ptr = ptr, .idx = 0 };
    }

    fn readAll(self: *Reader) []u8 {
        const res = self.ptr[self.idx..];
        self.idx = @intCast(self.ptr.len);
        return res;
    }

    fn readInt(self: *Reader, comptime T: type) T {
        const size = comptime @divExact(@typeInfo(T).Int.bits, 8);
        const res = std.mem.readInt(T, self.ptr[self.idx..][0..size], std.builtin.Endian.little);
        self.idx += size;
        return res;
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
};

const CustomData = struct {};
const Header = struct { encAlgo: ?[]u8, compAlgo: ?Compression, masterSalt: ?[]u8, nonce: ?[]u8, kdfParams: ?KdfParams, customData: ?CustomData };
const InnerHeader = struct { innerEncAlgo: ?u32, innerEncKey: ?[]u8, binaryContent: ?[]u8 };

fn parseKdfParams(r: *Reader) Error!KdfParams {
    var kdfParams: ?KdfParams = null;
    const v = r.readInt(u16);

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
                const nameSize = r.readInt(u32);
                const name = r.readN(nameSize);
                const valueSize = r.readInt(u32);

                if (std.mem.eql(u8, name, "$UUID")) {
                    const value = r.readN(valueSize);
                    if (std.mem.eql(u8, value, &uuid.aes256)) {
                        kdfParams = KdfParams{ .aesKdf = AesKdfParams{ .salt = null, .rounds = null } };
                    } else if (std.mem.eql(u8, value, &uuid.argon2d) or std.mem.eql(u8, value, &uuid.argon2id)) {
                        kdfParams = KdfParams{ .argon2 = Argon2Params{
                            .isHybrid = std.mem.eql(u8, value, &uuid.argon2id),
                            .version = null,
                            .salt = null,
                            .it = null,
                            .mem = null,
                            .par = null,
                        } };
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
                                params.*.rounds = r.readInt(u64);
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
                                params.*.version = r.readInt(u32);
                            } else if (std.mem.eql(u8, name, "S")) {
                                params.*.salt = r.readN(valueSize);
                            } else if (std.mem.eql(u8, name, "I")) {
                                params.*.it = r.readInt(u64);
                            } else if (std.mem.eql(u8, name, "M")) {
                                params.*.mem = r.readInt(u64);
                            } else if (std.mem.eql(u8, name, "P")) {
                                params.*.par = r.readInt(u32);
                            } else {
                                return Error.CorruptedHeader;
                            }
                        },
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

fn parseInnerHeader(r: *Reader) Error!InnerHeader {
    var innerHeader = InnerHeader{ .innerEncAlgo = null, .innerEncKey = null, .binaryContent = null };

    // TODO: add checks whether all fields were set
    while (true) {
        const kind = r.readByte();
        const size = r.readInt(u32);

        switch (kind) {
            0 => {
                // end of header
                return innerHeader;
            },
            1 => {
                // inner encryption algorithm, int32
                std.debug.assert(size == 4);
                innerHeader.innerEncAlgo = r.readInt(u32);
            },
            2 => {
                // inner encryption key, bytes
                innerHeader.innerEncKey = r.readN(size);
            },
            3 => {
                // binary content, bytes
                innerHeader.binaryContent = r.readN(size);
            },
            else => {
                std.debug.print("kind: {}\n", .{kind});
                return Error.CorruptedInnerHeader;
            },
        }
    }
}

fn parseHeader(r: *Reader) Error!Header {
    var header: Header = Header{ .encAlgo = null, .compAlgo = null, .masterSalt = null, .nonce = null, .kdfParams = null, .customData = null };

    while (true) {
        const id = r.readByte();
        const size = r.readInt(u32);

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
                header.compAlgo = @enumFromInt(r.readInt(u32));
            },
            4 => {
                // compression algorithm uint32, we only use the first byte as this is 0 or 1
                std.debug.assert(size == 32);
                header.masterSalt = r.readN(size);
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
                std.debug.print("id: {}\n", .{id});
                return Error.CorruptedHeader;
            },
        }
    }
}

fn readSignature(r: *Reader) Error!void {
    const sig1 = r.readInt(u32);
    if (sig1 != 0x9aa2d903) {
        return Error.CorruptedSignature;
    }

    const sig2 = r.readInt(u32);
    if (sig2 != 0xb54bfb67) {
        return Error.CorruptedSignature;
    }

    const version = r.readInt(u32);
    std.debug.print("version: {x}\n", .{version});
}

pub fn read_kdbx(allocator: std.mem.Allocator, r: *Reader, finalPasswd: []u8) Error!void {
    // TODO: add proper version checking

    try readSignature(r);
    const header = try parseHeader(r);
    // TODO: Clean up this mess

    var derivedKey: [32]u8 = undefined;
    try kdf.deriveKey(allocator, header.kdfParams.?, finalPasswd, &derivedKey);
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

    // TODO: Parallelize reading of blocks and compression
    var blockIdx: u64 = 0;
    var decompressed = std.ArrayList(u8).initCapacity(allocator, r.ptr.len * 10) catch return Error.OutOfMemory;
    defer decompressed.deinit();
    var writer = decompressed.writer();

    while (true) {
        const blockHmac = r.readN(32);
        const dataSize = r.readInt(u32);

        if (dataSize == 0) {
            break;
        }

        const m = r.readN(dataSize);
        const block = allocator.alloc(u8, 8 + 4 + m.len) catch return Error.OutOfMemory;
        const idxBytes = intToBytes(u64, blockIdx);
        const sizeBytes = intToBytes(u32, dataSize);
        @memcpy(block[0..8], &idxBytes);
        @memcpy(block[8..12], &sizeBytes);
        @memcpy(block[block.len - m.len .. block.len], m);

        var blockKey: [64]u8 = undefined;
        // TODO: Optimize this to only increment and not concatenate every time
        const blockHmacConcated = idxBytes ++ intermediateHash;
        sha2.Sha512.hash(&blockHmacConcated, &blockKey, .{});

        var blockHmacActual: [32]u8 = undefined;
        hmac.sha2.HmacSha256.create(&blockHmacActual, block, &blockKey);

        if (!std.mem.eql(u8, blockHmac, &blockHmacActual)) {
            return Error.CorruptedBlock;
        }

        const decrypted: []u8 = try allocator.alloc(u8, dataSize);
        cbc_decrypt.cbc_aes256(&encryptionKey, header.nonce.?[0..16], decrypted, m);
        switch (header.compAlgo.?) {
            .none => {
                _ = writer.write(decrypted) catch return Error.OutOfMemory;
            },
            .gzip => {
                var fb = std.io.fixedBufferStream(decrypted);
                gzip.decompress(fb.reader(), writer) catch return Error.CorruptedCompression;
            },
        }

        blockIdx += 1;
    }

    var rInner = Reader.init(decompressed.items);
    const innerHeader = try parseInnerHeader(&rInner);
    std.debug.print("{}\n", .{innerHeader});
    std.debug.print("{s}\n", .{rInner.readAll()});
}
