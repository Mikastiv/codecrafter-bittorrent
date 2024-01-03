const std = @import("std");
const stdout = std.io.getStdOut().writer();
const allocator = std.heap.page_allocator;
const Sha1 = std.crypto.hash.Sha1;

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

        var win = std.mem.window(u8, torrent.info.pieces, 20, 20);

        try stdout.print("Tracker URL: {s}\n", .{torrent.tracker});
        try stdout.print("Length: {d}\n", .{torrent.info.length});
        try stdout.print("Info Hash: {s}\n", .{std.fmt.bytesToHex(torrent.info.hash, .lower)});
        try stdout.print("Piece Length: {d}\n", .{torrent.info.piece_length});
        try stdout.print("Piece Hashes:\n", .{});
        while (win.next()) |item| {
            try stdout.print("{s}\n", .{std.fmt.bytesToHex(item[0..20], .lower)});
        }
    } else if (std.mem.eql(u8, command, "peers")) {
        const filename = args[2];
        const torrent = try parseTorrentFile(filename);

        var query = std.ArrayList(u8).init(allocator);
        const writer = query.writer();
        try query.appendSlice("?info_hash=");
        try query.appendSlice(try std.Uri.escapeString(allocator, &torrent.info.hash));
        try query.append('&');
        try query.appendSlice("peer_id=00112233445566778899&");
        try query.appendSlice("port=6881&");
        try query.appendSlice("uploaded=0&");
        try query.appendSlice("downloaded=0&");
        try writer.print("left={d}&", .{torrent.info.length});
        try query.appendSlice("compact=1");

        const url = try std.mem.concat(allocator, u8, &.{torrent.tracker, query.items});
        const uri = try std.Uri.parse(url);

        var client = std.http.Client{ .allocator = allocator };
        var req = try client.request(.GET, uri, .{.allocator = allocator}, .{});
        try req.start();
        try req.finish();
        try req.wait();

        var body: [2048]u8 = undefined;
        const len = try req.readAll(&body);

        // const res = try client.fetch(allocator, .{
        //     .location = .{
        //         .uri = uri,
        //     },
        // });
        // if (res.body == null) return error.InvalidResponse;

        const decoded = decodeBencode(body[0..len]) catch {
            try stdout.print("Invalid encoded value\n", .{});
            std.os.exit(1);
        };
        if (decoded != .dict) return error.InvalidResponse;

        const peers_entry = decoded.dict.get("peers") orelse return error.InvalidResponse;
        if (peers_entry != .string) return error.InvalidResponse;

        var peers = std.mem.window(u8, peers_entry.string, 6, 6);
        while (peers.next()) |peer| {
            const ip = peer[0..4];
            const port = std.mem.bytesToValue(u16, peer[4..6]);
            try stdout.print("{d}.{d}.{d}.{d}:{d}\n", .{ ip[0], ip[1], ip[2], ip[3], std.mem.bigToNative(u16, port) });
        }
    }
}

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

    return .{
        .tracker = tracker.string,
        .info = .{
            .length = try std.fmt.parseInt(u32, length.int, 10),
            .piece_length = try std.fmt.parseInt(u32, piece_length.int, 10),
            .pieces = pieces.string,
            .hash = hash,
        },
    };
}

const Torrent = struct {
    tracker: []const u8,
    info: struct {
        length: u32,
        piece_length: u32,
        pieces: []const u8,
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
