const err = @import("error.zig");
const std = @import("std");
const sha2 = std.crypto.hash.sha2;
const hmac = std.crypto.auth.hmac;

fn validate_header(hmacHashKey: []u8, headerData: []u8, headerSha256: []u8, headerHmacSha256: []u8) err.Error!void {
    var headerShaActual: [32]u8 = undefined;
    sha2.Sha256.hash(headerData, &headerShaActual, .{});

    if (!std.mem.eql(u8, headerSha256, &headerShaActual)) {
        return err.Error.CorruptedHeader;
    }

    var headerHmacActual: [32]u8 = undefined;
    hmac.sha2.HmacSha256.create(&headerHmacActual, headerData, &hmacHashKey);

    if (!std.mem.eql(u8, headerHmacSha256, &headerHmacActual)) {
        return err.Error.InvalidCredentials;
    }
}
