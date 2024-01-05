const std = @import("std");
const stdout = std.io.getStdOut().writer();
const Sha1 = std.crypto.hash.Sha1;
const Torrent = @import("Torrent.zig");
const bencode = @import("bencode.zig");
const Message = @import("Message.zig");
const Peer = @import("Peer.zig");
const Piece = @import("Piece.zig");

const max_connected_peers = 3;

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

        const peers = try torrent.fetchPeerAddresses(allocator);
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

        const peers = try torrent.fetchPeerAddresses(allocator);
        defer allocator.free(peers);

        var peer = try Peer.init(allocator, peers[1], torrent.info.hash);
        defer peer.deinit();

        const reader = peer.stream.reader();
        const writer = peer.stream.writer();

        try Message.send(.{ .tag = .interested, .payload = &.{} }, writer);

        const unchoke = try Message.recv(allocator, reader);
        std.debug.assert(unchoke.tag == .unchoke);

        const piece = Piece.init(piece_index, &torrent.info);
        const piece_data = try piece.download(allocator, &peer);

        var hash: [Sha1.digest_length]u8 = undefined;
        Sha1.hash(piece_data, &hash, .{});

        std.debug.assert(std.mem.eql(u8, &hash, torrent.info.pieces[piece.index]));

        const output = try std.fs.cwd().createFile(output_file, .{});
        defer output.close();
        const file_writer = output.writer();

        try file_writer.writeAll(piece_data);

        try stdout.print("Piece {d} downloaded to {s}\n", .{ piece_index, output_file });
    } else if (std.mem.eql(u8, command, "download")) {
        const output_file = args[3];
        _ = output_file; // autofix
        const filename = args[4];
        const torrent = try Torrent.fromFile(allocator, filename);
        defer torrent.deinit();

        const peer_addresses = try torrent.fetchPeerAddresses(allocator);
        var available_peers = std.ArrayList(std.net.Address).fromOwnedSlice(allocator, peer_addresses);
        defer available_peers.deinit();

        var connected_peers = std.ArrayList(Peer).init(allocator);
        defer {
            for (connected_peers.items) |*peer| peer.deinit();
            connected_peers.deinit();
        }
    }
}
