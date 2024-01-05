const std = @import("std");
const Sha1 = std.crypto.hash.Sha1;
const bencode = @import("bencode.zig");

pub const Info = struct {
    length: u32,
    piece_length: u32,
    pieces: [][]const u8,
    hash: [Sha1.digest_length]u8,
};

allocator: std.mem.Allocator,
tracker_url: []const u8,
info: Info,

pub fn fromFile(allocator: std.mem.Allocator, filename: []const u8) !@This() {
    const file = try std.fs.cwd().openFile(filename, .{});
    defer file.close();

    const content = try file.readToEndAlloc(allocator, std.math.maxInt(usize));
    defer allocator.free(content);

    var decoded = try bencode.decode(allocator, content);
    defer decoded.free(allocator);

    if (decoded != .dict) return error.FileIsNotDictionary;

    const tracker_url = decoded.dict.get("announce") orelse return error.NoAnnounceKey;
    if (tracker_url != .string) return error.AnnounceNotString;

    const info_entry = decoded.dict.get("info") orelse return error.NoInfoKey;
    if (info_entry != .dict) return error.InfoNotDictionary;

    const info = info_entry.dict;

    const length = info.get("length") orelse return error.NoInfoLengthKey;
    if (length != .int) return error.InfoLengthNotInteger;

    const piece_length = info.get("piece length") orelse return error.NoInfoPieceLengthKey;
    if (piece_length != .int) return error.InfoPieceLengthNotInteger;

    const encoded_info = try bencode.encode(allocator, info_entry);
    defer allocator.free(encoded_info);
    var hash: [Sha1.digest_length]u8 = undefined;
    Sha1.hash(encoded_info, &hash, .{});

    const pieces = info.get("pieces") orelse return error.NoPiecesKey;
    if (pieces != .string) return error.InfoPiecesNotString;

    var window = std.mem.window(u8, pieces.string, 20, 20);
    var pcs = try std.ArrayList([]const u8).initCapacity(allocator, pieces.string.len / 20);
    while (window.next()) |piece| {
        try pcs.append(try allocator.dupe(u8, piece));
    }

    return .{
        .allocator = allocator,
        .tracker_url = try allocator.dupe(u8, tracker_url.string),
        .info = .{
            .length = @intCast(length.int),
            .piece_length = @intCast(piece_length.int),
            .pieces = try pcs.toOwnedSlice(),
            .hash = hash,
        },
    };
}

pub fn printInfo(self: *const @This(), writer: anytype) !void {
    try writer.print("Tracker URL: {s}\n", .{self.tracker_url});
    try writer.print("Length: {d}\n", .{self.info.length});
    try writer.print("Info Hash: {s}\n", .{std.fmt.bytesToHex(self.info.hash, .lower)});
    try writer.print("Piece Length: {d}\n", .{self.info.piece_length});
    try writer.print("Piece Hashes:\n", .{});
    for (self.info.pieces) |item| {
        try writer.print("{s}\n", .{std.fmt.bytesToHex(item[0..20], .lower)});
    }
}

pub fn fetchPeers(self: *const @This(), allocator: std.mem.Allocator) ![]std.net.Address {
    var query = std.ArrayList(u8).init(allocator);
    defer query.deinit();
    const writer = query.writer();

    const escaped_hash = try std.Uri.escapeString(allocator, &self.info.hash);
    defer allocator.free(escaped_hash);
    try writer.print(
        "?info_hash={s}&peer_id={s}&port={d}&uploaded={d}&downloaded={d}&left={d}&compact={d}",
        .{ escaped_hash, "00112233445566778899", 6881, 0, 0, self.info.length, 1 },
    );

    const url = try std.mem.concat(allocator, u8, &.{ self.tracker_url, query.items });
    defer allocator.free(url);
    const uri = try std.Uri.parse(url);

    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();
    var req = try client.request(.GET, uri, .{ .allocator = allocator }, .{});
    defer req.deinit();
    try req.start();
    try req.finish();
    try req.wait();

    var body: [4096]u8 = undefined;
    const len = try req.readAll(&body);

    var decoded = try bencode.decode(allocator, body[0..len]);
    defer decoded.free(allocator);
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

pub fn deinit(self: *const @This()) void {
    self.allocator.free(self.tracker_url);
    for (self.info.pieces) |piece| {
        self.allocator.free(piece);
    }
    self.allocator.free(self.info.pieces);
}
