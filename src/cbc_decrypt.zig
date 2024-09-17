const std = @import("std");
const aes = std.crypto.core.aes;

fn bytewiseXor(dest: []u8, other: []u8) void {
    std.debug.assert(dest.len == other.len);

    for (0..dest.len) |i| {
        dest[i] ^= other[i];
    }
}

pub fn cbc_aes256(
    key: *[32]u8, 
    iv: *[16]u8,
    dest: []u8, 
    source: []u8
) void {
    std.debug.assert(source.len % 16 == 0);
    std.debug.assert(dest.len == source.len);

    const dec = aes.Aes256.initDec(key.*);
    dec.decrypt(dest[0..16], source[0..16]);
    bytewiseXor(dest[0..16], iv[0..16]);

    for (1 .. source.len / 16) |i| {
        const start = i * 16;
        const end = i * 16 + 16;
        dec.decrypt(dest[start .. end][0..16], source[start .. end][0..16]);
        bytewiseXor(dest[start .. end], source[start - 16 .. end - 16]);
    }
}
