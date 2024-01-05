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

        var peer = try Peer.init(allocator, peers[2], torrent.info.hash);
        defer peer.deinit();

        const piece = Piece.init(piece_index, &torrent.info);
        const piece_data = try piece.download(allocator, &peer);
        defer allocator.free(piece_data);

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

        const max_peers = @min(3, available_peers.items.len);
        for (0..max_peers) |_| {
            const peer = Peer.init(allocator, available_peers.pop(), torrent.info.hash) catch continue;
            try connected_peers.append(peer);
        }

        var piece_count = torrent.info.length / torrent.info.piece_length;
        if (torrent.info.length % torrent.info.piece_length != 0) piece_count += 1;

        var piece_queue = std.TailQueue(Piece){};
        defer {
            while (piece_queue.pop()) |node| allocator.destroy(node);
        }

        for (0..piece_count) |idx| {
            var node = try allocator.create(std.TailQueue(Piece).Node);
            node.data = Piece.init(@intCast(idx), &torrent.info);
            piece_queue.append(node);
        }

        while (piece_queue.len > 0) {
            if (connected_peers.items.len < max_peers and available_peers.items.len > 0) {
                const peer = try Peer.init(allocator, available_peers.items[0], torrent.info.hash);
                _ = available_peers.orderedRemove(0);
                try connected_peers.append(peer);
            }

            const node = piece_queue.popFirst().?;
            const piece = node.data;
            const peer_idx = getPeerWithPiece(connected_peers.items, piece.index) orelse {
                piece_queue.append(node);
                continue;
            };

            const peer = connected_peers.items[peer_idx];
            const piece_data = piece.download(allocator, &peer) catch |err| {
                std.debug.print("{any}\n", .{err});
                piece_queue.append(node);
                var bad_peer = connected_peers.orderedRemove(peer_idx);
                try available_peers.append(bad_peer.addr);
                bad_peer.deinit();
                continue;
            };
            defer allocator.free(piece_data);

            allocator.destroy(node);

            var buffer: [256]u8 = undefined;
            const piece_name = try std.fmt.bufPrint(&buffer, "{s}-{d}", .{ output_file, piece.index });
            const output = try std.fs.cwd().createFile(piece_name, .{});
            defer output.close();
            const file_writer = output.writer();

            try file_writer.writeAll(piece_data);
        }

        const file = try std.fs.cwd().createFile(output_file, .{});
        defer file.close();
        const file_writer = file.writer();
        for (0..piece_count) |idx| {
            const piece_name = try std.fmt.allocPrint(allocator, "{s}-{d}", .{ output_file, idx });
            defer allocator.free(piece_name);
            const piece_file = try std.fs.cwd().openFile(piece_name, .{});
            const file_reader = piece_file.reader();

            var buffer: [4096]u8 = undefined;
            while (true) {
                const len = try file_reader.readAll(&buffer);
                try file_writer.writeAll(buffer[0..len]);
                if (len < buffer.len) break;
            }

            piece_file.close();
            try std.fs.cwd().deleteFile(piece_name);
        }
    }
}

fn getPeerWithPiece(peers: []const Peer, idx: u32) ?usize {
    for (peers, 0..) |peer, i| {
        if (peer.hasPiece(idx)) return i;
    }
    return null;
}
