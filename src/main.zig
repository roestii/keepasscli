const std = @import("std");
const c = @cImport({
    @cInclude("unistd.h");
});

const gzip = std.compress.gzip;
const sha2 = std.crypto.hash.sha2;

const uuid = @import("uuid.zig");
const err = @import("error.zig");
const kdbx_reader = @import("kdbx_reader.zig");

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

    const ptr = try std.posix.mmap(null, @intCast(md.size()), std.posix.PROT.READ | std.posix.PROT.WRITE, .{ .TYPE = .SHARED }, file.handle, 0);

    var r = kdbx_reader.Reader.init(ptr);
    try kdbx_reader.read_kdbx(allocator, &r, &finalPasswd);
}

test "simple test" {}
