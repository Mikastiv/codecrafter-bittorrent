const std = @import("std");

pub const Tag = enum(u8) {
    choke = 0,
    unchoke = 1,
    interested = 2,
    not_interested = 3,
    have = 4,
    bitfield = 5,
    request = 6,
    piece = 7,
    cancel = 8,
};

tag: Tag,
payload: []const u8,

pub fn send(self: @This(), writer: anytype) !void {
    const length: u32 = @intCast(self.payload.len + 1);
    try writer.writeIntBig(u32, length);
    try writer.writeByte(@intFromEnum(self.tag));
    try writer.writeAll(self.payload);
}

pub fn recv(allocator: std.mem.Allocator, reader: anytype) !@This() {
    var length: u32 = undefined;
    while (true) {
        length = try reader.readIntBig(u32);
        // 0 is keep alive
        if (length != 0) break;
    }

    const tag_byte = try reader.readByte();
    const tag = std.meta.intToEnum(Tag, tag_byte) catch return error.InvalidTag;
    var payload = try allocator.alloc(u8, length - 1);
    const len = try reader.readAll(payload);
    std.debug.assert(len == payload.len);

    return .{ .tag = tag, .payload = payload };
}
