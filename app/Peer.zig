const std = @import("std");
const Message = @import("Message.zig");

allocator: std.mem.Allocator,
addr: std.net.Address,
stream: std.net.Stream,
handshake: Handshake,
bitfield: Bitfield,

pub fn init(
    allocator: std.mem.Allocator,
    addr: std.net.Address,
    info_hash: [std.crypto.hash.Sha1.digest_length]u8,
) !@This() {
    const stream = try std.net.tcpConnectToAddress(addr);
    const handshake = try doHandshake(stream, info_hash);
    if (!std.mem.eql(u8, &handshake.info_hash, &info_hash)) return error.InfoHashMismatch;

    const reader = stream.reader();
    const writer = stream.writer();

    const bitfield = try Message.recv(allocator, reader);
    defer bitfield.deinit(allocator);

    if (bitfield.tag != .bitfield) return error.NoBitfieldMessage;

    try Message.send(.{ .tag = .interested, .payload = &.{} }, writer);

    const unchoke = try Message.recv(allocator, reader);
    if (unchoke.tag != .unchoke) return error.NoUnchokeMessage;

    return .{
        .allocator = allocator,
        .addr = addr,
        .stream = stream,
        .handshake = handshake,
        .bitfield = try Bitfield.init(allocator, bitfield.payload),
    };
}

pub fn deinit(self: *@This()) void {
    self.bitfield.deinit();
}

pub fn hasPiece(self: *const @This(), index: u32) bool {
    return self.bitfield.bits.isSet(index);
}

pub fn doHandshake(stream: std.net.Stream, info_hash: [20]u8) !Handshake {
    const writer = stream.writer();
    const reader = stream.reader();

    const handshake = Handshake{
        .info_hash = info_hash,
        .peer_id = "00112233445566778899".*,
    };
    try writer.writeStruct(handshake);
    return reader.readStruct(Handshake);
}

pub const Handshake = extern struct {
    protocol_length: u8 = 19,
    ident: [19]u8 = "BitTorrent protocol".*,
    reserved: [8]u8 = std.mem.zeroes([8]u8),
    info_hash: [20]u8,
    peer_id: [20]u8,
};

pub const Bitfield = struct {
    bits: std.DynamicBitSet,

    pub fn init(allocator: std.mem.Allocator, bits: []const u8) !@This() {
        const len = bits.len * @bitSizeOf(u8);
        var set = try std.DynamicBitSet.initEmpty(allocator, len);
        for (0..len) |idx| {
            const byte = idx / @bitSizeOf(u8);
            const bit = idx % @bitSizeOf(u8);
            const mask = @as(u8, 1) << @intCast(@bitSizeOf(u8) - 1 - bit);
            if (bits[byte] & mask != 0) set.set(idx);
        }

        return .{
            .bits = set,
        };
    }

    pub fn deinit(self: *@This()) void {
        self.bits.deinit();
    }
};

test "bitfield" {
    var field = try Bitfield.init(std.testing.allocator, &[_]u8{ 0b10001101, 0b01010100 });
    defer field.deinit();
    var it = field.bits.iterator(.{});
    try std.testing.expect(it.next().? == 0);
    try std.testing.expect(it.next().? == 4);
    try std.testing.expect(it.next().? == 5);
    try std.testing.expect(it.next().? == 7);
    try std.testing.expect(it.next().? == 9);
    try std.testing.expect(it.next().? == 11);
    try std.testing.expect(it.next().? == 13);
}
