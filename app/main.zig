const std = @import("std");
const stdout = std.io.getStdOut().writer();
const Sha1 = std.crypto.hash.Sha1;
const Torrent = @import("Torrent.zig");
const bencode = @import("bencode.zig");
const Message = @import("Message.zig");
const Peer = @import("Peer.zig");

const block_size = 16 * 1024;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 3) {
        try stdout.print("Usage: your_bittorrent.zig <command> <args>\n", .{});
        std.os.exit(1);
    }

    const command = args[1];

    if (std.mem.eql(u8, command, "decode")) {
        const encodedStr = args[2];
        var decoded = try bencode.decode(allocator, encodedStr);
        defer decoded.free(allocator);
        var string = std.ArrayList(u8).init(allocator);
        try decoded.writeJson(string.writer());
        const jsonStr = try string.toOwnedSlice();
        try stdout.print("{s}\n", .{jsonStr});
    } else if (std.mem.eql(u8, command, "info")) {
        const filename = args[2];
        const torrent = try Torrent.fromFile(allocator, filename);
        defer torrent.deinit();
        try torrent.printInfo(stdout);
    } else if (std.mem.eql(u8, command, "peers")) {
        const filename = args[2];
        const torrent = try Torrent.fromFile(allocator, filename);
        defer torrent.deinit();

        const peers = try torrent.fetchPeers(allocator);
        defer allocator.free(peers);
        for (peers) |peer| {
            try peer.format("", .{}, stdout);
            try stdout.print("\n", .{});
        }
    } else if (std.mem.eql(u8, command, "handshake")) {
        const filename = args[2];
        const torrent = try Torrent.fromFile(allocator, filename);
        defer torrent.deinit();

        var it = std.mem.splitScalar(u8, args[3], ':');
        const ip = it.first();
        const port = it.next() orelse return error.MissingPort;

        const address = try std.net.Address.resolveIp(ip, try std.fmt.parseInt(u16, port, 10));
        var peer = try Peer.init(allocator, address, torrent.info.hash);
        defer peer.deinit();

        try stdout.print("Peer ID: {s}\n", .{std.fmt.bytesToHex(peer.handshake.peer_id, .lower)});
    } else if (std.mem.eql(u8, command, "download_piece")) {
        const output_file = args[3];
        const filename = args[4];
        const piece_index = try std.fmt.parseInt(u32, args[5], 10);
        const torrent = try Torrent.fromFile(allocator, filename);
        defer torrent.deinit();

        if (piece_index >= torrent.info.pieces.len) return;

        const peers = try torrent.fetchPeers(allocator);
        defer allocator.free(peers);

        var peer = try Peer.init(allocator, peers[1], torrent.info.hash);
        defer peer.deinit();

        const reader = peer.stream.reader();
        const writer = peer.stream.writer();

        try Message.send(.{ .tag = .interested, .payload = &.{} }, writer);

        const unchoke = try Message.recv(allocator, reader);
        std.debug.assert(unchoke.tag == .unchoke);

        const piece_length = blk: {
            if (piece_index == torrent.info.pieces.len - 1) {
                const rem = torrent.info.length % torrent.info.piece_length;
                if (rem != 0) break :blk rem;
            }
            break :blk torrent.info.piece_length;
        };
        const piece = try allocator.alloc(u8, piece_length);
        defer allocator.free(piece);

        const full_blocks_count = piece_length / block_size;
        const last_block_size = piece_length % block_size;

        for (0..full_blocks_count) |i| {
            try Request.send(.{ .index = piece_index, .begin = @intCast(i * block_size), .length = block_size }, writer);

            const piece_block = try Message.recv(allocator, reader);
            defer allocator.free(piece_block.payload);
            std.debug.assert(piece_block.tag == .piece);
            const block = try Block.fromBytes(piece_block.payload);
            @memcpy(piece[block.begin .. block.begin + block.block.len], block.block);
        }

        if (last_block_size > 0) {
            try Request.send(.{ .index = piece_index, .begin = full_blocks_count * block_size, .length = last_block_size }, writer);

            const piece_block = try Message.recv(allocator, reader);
            defer allocator.free(piece_block.payload);
            std.debug.assert(piece_block.tag == .piece);
            const block = try Block.fromBytes(piece_block.payload);
            @memcpy(piece[block.begin .. block.begin + block.block.len], block.block);
        }

        var hash: [Sha1.digest_length]u8 = undefined;
        Sha1.hash(piece, &hash, .{});

        std.debug.assert(std.mem.eql(u8, &hash, torrent.info.pieces[piece_index]));

        const output = try std.fs.cwd().createFile(output_file, .{});
        defer output.close();
        const file_writer = output.writer();

        try file_writer.writeAll(piece);

        try stdout.print("Piece {d} downloaded to {s}\n", .{ piece_index, output_file });
    }
}

const Block = struct {
    const size = @sizeOf(@This());

    index: u32,
    begin: u32,
    block: []const u8,

    fn fromBytes(bytes: []const u8) !@This() {
        var stream = std.io.StreamSource{ .const_buffer = std.io.fixedBufferStream(bytes) };
        const reader = stream.reader();

        const index = try reader.readIntBig(u32);
        const begin = try reader.readIntBig(u32);
        const block = bytes[8..];

        return .{
            .index = index,
            .begin = begin,
            .block = block,
        };
    }
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
