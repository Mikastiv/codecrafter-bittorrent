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
    }
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
    }
}

const Decoded = union(enum) {
    string: []const u8,
    int: []const u8,
    list: []Decoded,

    fn len(self: @This()) usize {
        return switch (self) {
            .string => |str| str.len + countDigits(str.len) + 1,
            .int => |i| i.len + 2,
            .list => 0,
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

fn decodeBencode(encodedValue: []const u8) !Decoded {
    switch (encodedValue[0]) {
        '0'...'9' => {
            const firstColon = std.mem.indexOfScalar(u8, encodedValue, ':');
            if (firstColon == null) return error.InvalidArgument;

            const len = try std.fmt.parseInt(usize, encodedValue[0..firstColon.?], 10);
            const start = firstColon.? + 1;
            return .{ .string = encodedValue[start .. start + len] };
        },
        'i' => {
            const end = std.mem.indexOfScalar(u8, encodedValue, 'e');
            if (end == null) return error.InvalidArgument;

            return .{ .int = encodedValue[1..end.?] };
        },
        'l' => {
            const end = std.mem.lastIndexOfScalar(u8, encodedValue, 'e');
            if (end == null) return error.InvalidArgument;

            var list = std.ArrayList(Decoded).init(allocator);
            var current: usize = 1;
            while (current < end.?) {
                const next = try decodeBencode(encodedValue[current..end.?]);
                try list.append(next);
                if (next == .list)
                    current = end.?
                else
                    current += next.len();
            }
            return .{ .list = try list.toOwnedSlice() };
        },
        else => {
            try stdout.print("Only strings are supported at the moment\n", .{});
            std.os.exit(1);
        },
    }
}
