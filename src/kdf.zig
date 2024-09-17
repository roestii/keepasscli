const err = @import("error.zig");
const std = @import("std");
const argon2 = std.crypto.pwhash.argon2;

pub const AesKdfParams = struct { 
    salt: ?[]u8, 
    rounds: ?u64 
};

pub const Argon2Params = struct { 
    isHybrid: bool,
    version: ?u32,
    salt: ?[]u8,
    it: ?u64,
    mem: ?u64,
    par: ?u32
};

pub const KdfParams = union(enum) {
    aesKdf: AesKdfParams,
    argon2: Argon2Params,
};

pub fn deriveKey(
    allocator: std.mem.Allocator, 
    kdfParams: KdfParams, 
    finalPasswd: []u8,
    derivedKey: []u8, 
) err.Error!void {
    switch (kdfParams) {
        .aesKdf => |*params| {
            std.debug.print("aes-kdf params: {}", .{params.*});
            unreachable;
        },
        .argon2 => |*params| {
            // 32 byte is the length of the salt
            const mode: argon2.Mode = if (!params.*.isHybrid) .argon2d else .argon2id;
            argon2.kdf(
                allocator,
                derivedKey,
                finalPasswd,
                params.*.salt.?,
                .{
                    .t = @intCast(params.*.it.?),
                    // The api expects the memory to be in kibibytes
                    .m = @intCast(params.*.mem.? / 1024),
                    .p = @intCast(params.*.par.?)
                },
                mode
            ) catch return err.Error.UnsupportedKDF;
        }
    }
}
