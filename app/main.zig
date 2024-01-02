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
        switch (decoded) {
            .string => |str| try std.json.stringify(str, .{}, string.writer()),
            .int => |i| _ = try string.writer().write(i),
        }
        const jsonStr = try string.toOwnedSlice();
        try stdout.print("{s}\n", .{jsonStr});
    }
}

const DecodeResult = union(enum) {
    string: []const u8,
    int: []const u8,
};

fn decodeBencode(encodedValue: []const u8) !DecodeResult {
    switch (encodedValue[0]) {
        '0'...'9' => {
            const firstColon = std.mem.indexOf(u8, encodedValue, ":");
            if (firstColon == null) {
                return error.InvalidArgument;
            }
            return .{ .string = encodedValue[firstColon.? + 1 ..] };
        },
        'i' => {
            const end = std.mem.indexOfScalar(u8, encodedValue, 'e');
            if (encodedValue.len < 1 or encodedValue[encodedValue.len - 1] != 'e') return error.InvalidArgument;
            return .{ .int = encodedValue[1..end.?] };
        },
        else => {
            try stdout.print("Only strings are supported at the moment\n", .{});
            std.os.exit(1);
        },
    }
}
