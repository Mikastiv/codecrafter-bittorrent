const std = @import("std");
const Torrent = @import("Torrent.zig");
const Peer = @import("Peer.zig");
const Message = @import("Message.zig");

const block_size = 16 * 1024;

index: u32,
length: u32,
block_count: u32,
last_block_different: bool,

pub fn init(index: u32, info: *const Torrent.Info) @This() {
    const is_last_piece = index == info.pieces.len - 1;
    const piece_length = blk: {
        if (is_last_piece) {
            const rem = info.length % info.piece_length;
            if (rem != 0) break :blk rem;
        }
        break :blk info.piece_length;
    };

    var block_count = piece_length / block_size;
    const last_block_different = piece_length % block_size != 0;
    if (last_block_different) block_count += 1;

    return .{
        .index = index,
        .length = piece_length,
        .block_count = block_count,
        .last_block_different = last_block_different,
    };
}

pub fn download(self: @This(), allocator: std.mem.Allocator, peer: *const Peer) ![]const u8 {
    const writer = peer.stream.writer();
    const reader = peer.stream.reader();

    const piece_data = try allocator.alloc(u8, self.length);
    errdefer allocator.free(piece_data);

    var it = self.blocks();
    while (it.next()) |block| {
        try Request.send(.{ .index = self.index, .begin = block.begin, .length = block.length }, writer);

        const piece_block = try Message.recv(allocator, reader);
        defer piece_block.deinit(allocator);
        std.debug.assert(piece_block.tag == .piece);
        const recv_block = try ReceivedBlock.fromBytes(piece_block.payload);
        @memcpy(piece_data[block.begin .. block.begin + block.length], recv_block.data);
    }

    return piece_data;
}

pub fn blocks(self: @This()) BlockIterator {
    return .{
        .index = 0,
        .piece_length = self.length,
        .block_count = self.block_count,
        .last_block_different = self.last_block_different,
    };
}

pub const BlockIterator = struct {
    index: u32,
    piece_length: u32,
    block_count: u32,
    last_block_different: bool,

    fn next(self: *@This()) ?Block {
        if (self.index >= self.block_count) return null;

        const index = self.index;
        self.index += 1;

        const length = if (self.last_block_different and index == self.block_count - 1)
            self.piece_length % block_size
        else
            block_size;

        return .{
            .begin = index * block_size,
            .length = length,
        };
    }
};

pub const Block = struct {
    begin: u32,
    length: u32,
};

const Request = struct {
    const size = @sizeOf(@This());

    index: u32,
    begin: u32,
    length: u32,

    fn send(self: @This(), writer: anytype) !void {
        const length = @This().size + 1;
        const tag: u8 = @intFromEnum(Message.Tag.request);
        try writer.writeIntBig(u32, length);
        try writer.writeByte(tag);
        try writer.writeIntBig(u32, self.index);
        try writer.writeIntBig(u32, self.begin);
        try writer.writeIntBig(u32, self.length);
    }
};

const ReceivedBlock = struct {
    const size = @sizeOf(@This());

    index: u32,
    begin: u32,
    data: []const u8,

    fn fromBytes(bytes: []const u8) !@This() {
        var stream = std.io.StreamSource{ .const_buffer = std.io.fixedBufferStream(bytes) };
        const reader = stream.reader();

        const index = try reader.readIntBig(u32);
        const begin = try reader.readIntBig(u32);
        const data = bytes[@sizeOf(u32) * 2 ..];

        return .{
            .index = index,
            .begin = begin,
            .data = data,
        };
    }
};
