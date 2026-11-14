//! Framing shared by the client and server: a fixed size `Packet` header, optionally
//! followed by `transfer_len - Packet.wire_size` bytes of payload.
const std = @import("std");
const net = std.Io.net;
const Packet = @import("pack.zig").Packet;
const Serializer = @import("serializer.zig");

pub const magic: u8 = 0xAF;

/// Header for a reply to `request`, same token and command.
pub fn reply_packet(request: Packet) Packet {
    return .{
        .magic = magic,
        .token = request.token,
        .command = request.command,
    };
}

pub fn append_payload_len(packet: *Packet, payload_len: usize) error{PayloadTooLarge}!void {
    const len = std.math.cast(u32, payload_len) orelse return error.PayloadTooLarge;
    packet.transfer_len = std.math.add(u32, packet.transfer_len, len) catch return error.PayloadTooLarge;
}

pub fn write_packet(io: std.Io, packet: Packet, stream: net.Stream) !void {
    var bytes: [Packet.wire_size]u8 = undefined;
    var wbuff: [Packet.wire_size]u8 = undefined;
    std.mem.writeInt(Packet.Int, &bytes, @bitCast(packet), .little);
    var writer = stream.writer(io, &wbuff);
    const w = &writer.interface;
    try w.writeAll(&bytes);
    try w.flush();
}

pub fn write_payload(io: std.Io, payload: []const u8, stream: net.Stream) !void {
    var wbuff: [128]u8 = undefined;
    var writer = stream.writer(io, &wbuff);
    const w = &writer.interface;
    try w.writeAll(payload);
    try w.flush();
}

pub fn read_packet(r: *std.Io.Reader) !Packet {
    const packet: Packet = @bitCast(try r.takeInt(Packet.Int, .little));

    if (packet.magic != magic) return error.InvalidMagic;
    if (packet.transfer_len < Packet.wire_size) return error.InvalidTransferLen;

    return packet;
}

pub fn read_payload(alloc: std.mem.Allocator, packet: Packet, r: *std.Io.Reader) !Serializer.Bytes {
    return .init(alloc, try r.readAlloc(alloc, packet.transfer_len - Packet.wire_size));
}
