const std = @import("std");
const stdout = std.io.getStdOut().writer();
const allocator = std.heap.page_allocator;

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
        const file = try std.fs.cwd().openFile(filename, .{});
        const content = try file.readToEndAlloc(allocator, std.math.maxInt(usize));
        const decoded = decodeBencode(content) catch {
            try stdout.print("Invalid encoded value\n", .{});
            std.os.exit(1);
        };

        if (decoded != .dict) invalidTorrentFile();

        const tracker = decoded.dict.get("announce");
        const info = decoded.dict.get("info");

        if (tracker == null or info == null) invalidTorrentFile();
        if (info.? != .dict) invalidTorrentFile();

        const length = info.?.dict.get("length");
        if (length == null) invalidTorrentFile();

        const encoded_info = try encodeBencode(info.?);
        var hash: [std.crypto.hash.Sha1.digest_length]u8 = undefined;
        std.crypto.hash.Sha1.hash(encoded_info, &hash, .{});

        try stdout.print("Tracker URL: {s}\n", .{tracker.?.string});
        try stdout.print("Length: {s}\n", .{length.?.int});
        try stdout.print("Info Hash: {s}\n", .{std.fmt.bytesToHex(hash, .lower)});
    }
}

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
