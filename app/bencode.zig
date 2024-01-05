const std = @import("std");

pub const Decoded = union(enum) {
    string: []const u8,
    int: i32,
    list: []Decoded,
    dict: std.StringArrayHashMap(Decoded),

    fn len(self: @This()) usize {
        return switch (self) {
            .string => |str| str.len + countDigits(usize, str.len) + 1,
            .int => |int| countDigits(isize, int) + 2,
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
                    count += item.key_ptr.len + countDigits(usize, item.key_ptr.len) + 1;
                    count += item.value_ptr.len();
                }
                break :blk count;
            },
        };
    }

    pub fn writeJson(self: @This(), writer: anytype) !void {
        switch (self) {
            .string => |str| try std.json.stringify(str, .{}, writer),
            .int => |int| try writer.print("{d}", .{int}),
            .list => |list| {
                try writer.writeByte('[');
                for (list, 0..) |item, i| {
                    try writeJson(item, writer);
                    if (i != list.len - 1) try writer.writeByte(',');
                }
                try writer.writeByte(']');
            },
            .dict => |dict| {
                try writer.writeByte('{');
                var it = dict.iterator();
                var i: usize = 0;
                while (it.next()) |item| : (i += 1) {
                    try writeJson(.{ .string = item.key_ptr.* }, writer);
                    try writer.writeByte(':');
                    try writeJson(item.value_ptr.*, writer);
                    if (i != dict.count() - 1) try writer.writeByte(',');
                }
                try writer.writeByte('}');
            },
        }
    }

    pub fn free(self: *@This(), allocator: std.mem.Allocator) void {
        switch (self.*) {
            .string => |str| allocator.free(str),
            .int => {},
            .list => |list| {
                for (list) |*item| {
                    item.free(allocator);
                }
                allocator.free(list);
            },
            .dict => |*dict| {
                var it = dict.iterator();
                while (it.next()) |item| {
                    allocator.free(item.key_ptr.*);
                    item.value_ptr.free(allocator);
                }
                dict.deinit();
            },
        }
    }
};

fn countDigits(comptime T: type, n: T) usize {
    var count: usize = 1;
    var num = n;
    if (@typeInfo(T).Int.signedness == .signed) {
        std.debug.assert(n != std.math.minInt(T));
        if (n < 0) {
            count += 1;
            num *= -1;
        }
    }
    while (num > 9) : (count += 1) {
        num = @divTrunc(num, 10);
    }
    return count;
}

pub fn decode(allocator: std.mem.Allocator, encoded_value: []const u8) !Decoded {
    switch (encoded_value[0]) {
        '0'...'9' => {
            const firstColon = std.mem.indexOfScalar(u8, encoded_value, ':');
            if (firstColon == null) return error.InvalidArgument;

            const len = try std.fmt.parseInt(usize, encoded_value[0..firstColon.?], 10);
            const start = firstColon.? + 1;
            const str = try allocator.dupe(u8, encoded_value[start .. start + len]);
            return .{ .string = str };
        },
        'i' => {
            const end = std.mem.indexOfScalar(u8, encoded_value, 'e');
            if (end == null) return error.InvalidArgument;

            const int = try std.fmt.parseInt(i32, encoded_value[1..end.?], 10);
            return .{ .int = int };
        },
        'l' => {
            var list = std.ArrayList(Decoded).init(allocator);
            var current: usize = 1;
            while (encoded_value[current] != 'e' and current < encoded_value.len) {
                const next = try decode(allocator, encoded_value[current..]);
                try list.append(next);
                current += next.len();
            }
            return .{ .list = try list.toOwnedSlice() };
        },
        'd' => {
            var dict = std.StringArrayHashMap(Decoded).init(allocator);
            var current: usize = 1;
            while (encoded_value[current] != 'e' and current < encoded_value.len) {
                const key = try decode(allocator, encoded_value[current..]);
                current += key.len();
                const value = try decode(allocator, encoded_value[current..]);
                try dict.put(key.string, value);
                current += value.len();
            }
            return .{ .dict = dict };
        },
        else => return error.InvalidBencodeCharacter,
    }
}

pub fn encode(allocator: std.mem.Allocator, decoded_value: Decoded) ![]const u8 {
    var output = std.ArrayList(u8).init(allocator);
    const writer = output.writer();
    switch (decoded_value) {
        .string => |str| try writer.print("{d}:{s}", .{ str.len, str }),
        .int => |int| try writer.print("i{d}e", .{int}),
        .list => |list| {
            try writer.writeByte('l');
            for (list) |item| {
                const encoded = try encode(allocator, item);
                defer allocator.free(encoded);
                try output.appendSlice(encoded);
            }
            try writer.writeByte('e');
        },
        .dict => |dict| {
            try writer.writeByte('d');
            var it = dict.iterator();
            while (it.next()) |item| {
                const encoded_key = try encode(allocator, .{ .string = item.key_ptr.* });
                defer allocator.free(encoded_key);
                const encoded_value = try encode(allocator, item.value_ptr.*);
                defer allocator.free(encoded_value);
                try output.appendSlice(encoded_key);
                try output.appendSlice(encoded_value);
            }
            try writer.writeByte('e');
        },
    }
    return output.toOwnedSlice();
}
