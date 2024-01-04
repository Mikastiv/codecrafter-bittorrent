const std = @import("std");
const stdout = std.io.getStdOut().writer();
const allocator = std.heap.page_allocator;
const Sha1 = std.crypto.hash.Sha1;

const block_size = 16 * 1024;

pub fn main() !void {
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 3) {
        try stdout.print("Usage: your_bittorrent.zig <command> <args>\n", .{});
        std.os.exit(1);
    }

    const command = args[1];

    if (std.mem.eql(u8, command, "decode")) {
        const encodedStr = args[2];
        const decoded = decodeBencode(encodedStr) catch {
            try stdout.print("Invalid encoded value\n", .{});
            std.os.exit(1);
        };
        var string = std.ArrayList(u8).init(allocator);
        try writeDecoded(decoded, string.writer());
        const jsonStr = try string.toOwnedSlice();
        try stdout.print("{s}\n", .{jsonStr});
    } else if (std.mem.eql(u8, command, "info")) {
        const filename = args[2];
        const torrent = try parseTorrentFile(filename);

        try stdout.print("Tracker URL: {s}\n", .{torrent.tracker});
        try stdout.print("Length: {d}\n", .{torrent.info.length});
        try stdout.print("Info Hash: {s}\n", .{std.fmt.bytesToHex(torrent.info.hash, .lower)});
        try stdout.print("Piece Length: {d}\n", .{torrent.info.piece_length});
        try stdout.print("Piece Hashes:\n", .{});
        for (torrent.info.pieces) |item| {
            try stdout.print("{s}\n", .{std.fmt.bytesToHex(item[0..20], .lower)});
        }
    } else if (std.mem.eql(u8, command, "peers")) {
        const filename = args[2];
        const torrent = try parseTorrentFile(filename);

        const peers = try getPeers(&torrent);
        for (peers) |peer| {
            try peer.format("", .{}, stdout);
            try stdout.print("\n", .{});
        }
    } else if (std.mem.eql(u8, command, "handshake")) {
        const filename = args[2];
        const torrent = try parseTorrentFile(filename);

        var it = std.mem.splitScalar(u8, args[3], ':');
        const ip = it.first();
        const port = it.next() orelse return error.MissingPort;

        const address = try std.net.Address.resolveIp(ip, try std.fmt.parseInt(u16, port, 10));
        var stream = try std.net.tcpConnectToAddress(address);

        const handshake = try doHandshake(stream, torrent.info.hash);
        try stdout.print("Peer ID: {s}\n", .{std.fmt.bytesToHex(handshake.peer_id, .lower)});
    } else if (std.mem.eql(u8, command, "download_piece")) {
        const output_file = args[3];
        const filename = args[4];
        const piece_index = try std.fmt.parseInt(u32, args[5], 10);
        const torrent = try parseTorrentFile(filename);

        if (torrent.info.pieces.len >= piece_index) return;

        const peers = try getPeers(&torrent);
        const stream = try std.net.tcpConnectToAddress(peers[2]);
        const handshake = try doHandshake(stream, torrent.info.hash);
        std.debug.assert(std.mem.eql(u8, &handshake.info_hash, &torrent.info.hash));

        const reader = stream.reader();
        const writer = stream.writer();

        const bitfield = try Message.recv(reader);
        std.debug.assert(bitfield.tag == .bitfield);

        try Message.send(.{ .tag = .interested, .payload = &.{} }, writer);

        const unchoke = try Message.recv(reader);
        std.debug.assert(unchoke.tag == .unchoke);

        const full_blocks_count = torrent.info.piece_length / block_size;
        const last_block_size = torrent.info.piece_length % block_size;

        const piece = try allocator.alloc(u8, torrent.info.piece_length);

        for (0..full_blocks_count) |i| {
            try Request.send(.{ .index = piece_index, .begin = @intCast(i * block_size), .length = block_size }, writer);

            const piece_block = try Message.recv(reader);
            std.debug.assert(piece_block.tag == .piece);
            const block = try Block.fromBytes(piece_block.payload);
            @memcpy(piece[block.begin .. block.begin + block.block.len], block.block);
        }

        if (last_block_size > 0) {
            try Request.send(.{ .index = piece_index, .begin = full_blocks_count * block_size, .length = last_block_size }, writer);

            const piece_block = try Message.recv(reader);
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

fn readUntilMessage(reader: std.net.Stream.Reader, msg_type: Message.Type) !Message.Header {
    var header: Message.RawHeader = undefined;
    while (true) {
        header = try reader.readStructBig(Message.RawHeader);
        if (@as(Message.Type, @enumFromInt(header.id)) == msg_type) break;
    }
    return .{ .length = header.length, .id = @enumFromInt(header.id) };
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

const Message = struct {
    const Tag = enum(u8) {
        choke = 0,
        unchoke = 1,
        interested = 2,
        not_interested = 3,
        have = 4,
        bitfield = 5,
        request = 6,
        piece = 7,
        cancel = 8,
        heartbeat,
    };

    tag: Tag,
    payload: []const u8,

    fn send(self: @This(), writer: anytype) !void {
        const length: u32 = @intCast(self.payload.len + 1);
        try writer.writeIntBig(u32, length);
        try writer.writeByte(@intFromEnum(self.tag));
        try writer.writeAll(self.payload);
    }

    fn recv(reader: anytype) !@This() {
        var length: u32 = undefined;
        while (true) {
            length = try reader.readIntBig(u32);
            if (length != 0) break;
        }

        const tag_byte = try reader.readByte();
        const tag = std.meta.intToEnum(Tag, tag_byte) catch return error.InvalidTag;
        var payload = try allocator.alloc(u8, length - 1);
        const len = try reader.readAll(payload);
        std.debug.assert(len == payload.len);

        return .{ .tag = tag, .payload = payload };
    }
};

fn doHandshake(stream: std.net.Stream, info_hash: [20]u8) !Handshake {
    const writer = stream.writer();
    const reader = stream.reader();

    const handshake = Handshake{
        .info_hash = info_hash,
        .peer_id = "00112233445566778899".*,
    };
    try writer.writeStruct(handshake);

    return reader.readStruct(Handshake);
}

fn getPeers(torrent: *const Torrent) ![]std.net.Address {
    var query = std.ArrayList(u8).init(allocator);
    const writer = query.writer();
    const escaped_hash = try std.Uri.escapeString(allocator, &torrent.info.hash);
    try writer.print(
        "?info_hash={s}&peer_id=00112233445566778899&port=6881&uploaded=0&downloaded=0&left={d}&compact=1",
        .{ escaped_hash, torrent.info.length },
    );

    const url = try std.mem.concat(allocator, u8, &.{ torrent.tracker, query.items });
    const uri = try std.Uri.parse(url);

    // const res = try client.fetch(allocator, .{
    //     .location = .{
    //         .uri = uri,
    //     },
    // });
    // if (res.body == null) return error.InvalidResponse;

    var client = std.http.Client{ .allocator = allocator };
    var req = try client.request(.GET, uri, .{ .allocator = allocator }, .{});
    try req.start();
    try req.finish();
    try req.wait();

    var body: [4096]u8 = undefined;
    const len = try req.readAll(&body);

    const decoded = decodeBencode(body[0..len]) catch {
        try stdout.print("Invalid encoded value\n", .{});
        std.os.exit(1);
    };
    if (decoded != .dict) return error.InvalidResponse;

    const peers_entry = decoded.dict.get("peers") orelse return error.InvalidResponse;
    if (peers_entry != .string) return error.InvalidResponse;

    var peers = std.ArrayList(std.net.Address).init(allocator);
    var window = std.mem.window(u8, peers_entry.string, 6, 6);
    while (window.next()) |peer| {
        const ip = peer[0..4];
        const port = std.mem.bytesToValue(u16, peer[4..6]);
        const addr = std.net.Address.initIp4(ip.*, std.mem.bigToNative(u16, port));
        try peers.append(addr);
    }

    return peers.toOwnedSlice();
}

const Handshake = extern struct {
    protocol_length: u8 = 19,
    ident: [19]u8 = "BitTorrent protocol".*,
    reserved: [8]u8 = std.mem.zeroes([8]u8),
    info_hash: [20]u8,
    peer_id: [20]u8,
};

fn parseTorrentFile(filename: []const u8) !Torrent {
    const file = try std.fs.cwd().openFile(filename, .{});
    const content = try file.readToEndAlloc(allocator, std.math.maxInt(usize));
    const decoded = decodeBencode(content) catch {
        try stdout.print("Invalid encoded value\n", .{});
        std.os.exit(1);
    };

    if (decoded != .dict) return error.InvalidTorrentFile;

    const tracker = decoded.dict.get("announce") orelse return error.InvalidTorrentFile;
    if (tracker != .string) return error.InvalidTorrentFile;
    const info_entry = decoded.dict.get("info") orelse return error.InvalidTorrentFile;
    if (info_entry != .dict) return error.InvalidTorrentFile;

    const info = info_entry.dict;

    const length = info.get("length") orelse return error.InvalidTorrentFile;
    if (length != .int) return error.InvalidTorrentFile;

    const piece_length = info.get("piece length") orelse return error.InvalidTorrentFile;
    if (piece_length != .int) return error.InvalidTorrentFile;

    const encoded_info = try encodeBencode(info_entry);
    var hash: [Sha1.digest_length]u8 = undefined;
    Sha1.hash(encoded_info, &hash, .{});

    const pieces = info.get("pieces") orelse return error.InvalidTorrentFile;
    if (pieces != .string) return error.InvalidTorrentFile;

    var window = std.mem.window(u8, pieces.string, 20, 20);
    var pcs = std.ArrayList([]const u8).init(allocator);
    while (window.next()) |piece| {
        try pcs.append(piece);
    }

    return .{
        .tracker = tracker.string,
        .info = .{
            .length = try std.fmt.parseInt(u32, length.int, 10),
            .piece_length = try std.fmt.parseInt(u32, piece_length.int, 10),
            .pieces = try pcs.toOwnedSlice(),
            .hash = hash,
        },
    };
}

const Torrent = struct {
    tracker: []const u8,
    info: struct {
        length: u32,
        piece_length: u32,
        pieces: [][]const u8,
        hash: [Sha1.digest_length]u8,
    },
};

fn invalidTorrentFile() void {
    stdout.print("Invalid torrent file\n", .{}) catch {};
    std.os.exit(1);
}

fn writeDecoded(value: Decoded, writer: std.ArrayList(u8).Writer) !void {
    switch (value) {
        .string => |str| try std.json.stringify(str, .{}, writer),
        .int => |i| _ = try writer.writeAll(i),
        .list => |list| {
            try writer.writeByte('[');
            for (list, 0..) |item, i| {
                try writeDecoded(item, writer);
                if (i != list.len - 1) try writer.writeByte(',');
            }
            try writer.writeByte(']');
        },
        .dict => |dict| {
            try writer.writeByte('{');
            var it = dict.iterator();
            var i: usize = 0;
            while (it.next()) |item| : (i += 1) {
                try writeDecoded(.{ .string = item.key_ptr.* }, writer);
                try writer.writeByte(':');
                try writeDecoded(item.value_ptr.*, writer);
                if (i != dict.count() - 1) try writer.writeByte(',');
            }
            try writer.writeByte('}');
        },
    }
}

const Decoded = union(enum) {
    string: []const u8,
    int: []const u8,
    list: []Decoded,
    dict: std.StringArrayHashMap(Decoded),

    fn len(self: @This()) usize {
        return switch (self) {
            .string => |str| str.len + countDigits(str.len) + 1,
            .int => |i| i.len + 2,
            .list => |list| blk: {
                var count: usize = 2;
                for (list) |item| {
                    count += item.len();
                }
                break :blk count;
            },
            .dict => |dict| blk: {
                var count: usize = 2;
                var it = dict.iterator();
                while (it.next()) |item| {
                    count += item.key_ptr.len + countDigits(item.key_ptr.len) + 1;
                    count += item.value_ptr.len();
                }
                break :blk count;
            },
        };
    }
};

fn countDigits(n: usize) usize {
    var count: usize = 1;
    var num = n;
    while (num > 9) : (count += 1) {
        num /= 10;
    }
    return count;
}

fn decodeBencode(encoded_value: []const u8) !Decoded {
    switch (encoded_value[0]) {
        '0'...'9' => {
            const firstColon = std.mem.indexOfScalar(u8, encoded_value, ':');
            if (firstColon == null) return error.InvalidArgument;

            const len = try std.fmt.parseInt(usize, encoded_value[0..firstColon.?], 10);
            const start = firstColon.? + 1;
            return .{ .string = encoded_value[start .. start + len] };
        },
        'i' => {
            const end = std.mem.indexOfScalar(u8, encoded_value, 'e');
            if (end == null) return error.InvalidArgument;

            return .{ .int = encoded_value[1..end.?] };
        },
        'l' => {
            var list = std.ArrayList(Decoded).init(allocator);
            var current: usize = 1;
            while (encoded_value[current] != 'e' and current < encoded_value.len) {
                const next = try decodeBencode(encoded_value[current..]);
                try list.append(next);
                current += next.len();
            }
            return .{ .list = try list.toOwnedSlice() };
        },
        'd' => {
            var dict = std.StringArrayHashMap(Decoded).init(allocator);
            var current: usize = 1;
            while (encoded_value[current] != 'e' and current < encoded_value.len) {
                const key = try decodeBencode(encoded_value[current..]);
                current += key.len();
                const value = try decodeBencode(encoded_value[current..]);
                try dict.put(key.string, value);
                current += value.len();
            }
            return .{ .dict = dict };
        },
        else => {
            try stdout.print("Only strings are supported at the moment\n", .{});
            std.os.exit(1);
        },
    }
}

fn encodeBencode(decoded_value: Decoded) ![]const u8 {
    var output = std.ArrayList(u8).init(allocator);
    const writer = output.writer();
    switch (decoded_value) {
        .string => |s| try writer.print("{d}:{s}", .{ s.len, s }),
        .int => |i| try writer.print("i{s}e", .{i}),
        .list => |list| {
            try writer.writeByte('l');
            for (list) |item| {
                const encoded = try encodeBencode(item);
                try output.appendSlice(encoded);
            }
            try writer.writeByte('e');
        },
        .dict => |dict| {
            try writer.writeByte('d');
            var it = dict.iterator();
            while (it.next()) |item| {
                const encoded_key = try encodeBencode(.{ .string = item.key_ptr.* });
                const encoded_value = try encodeBencode(item.value_ptr.*);
                try output.appendSlice(encoded_key);
                try output.appendSlice(encoded_value);
            }
            try writer.writeByte('e');
        },
    }
    return output.toOwnedSlice();
}
