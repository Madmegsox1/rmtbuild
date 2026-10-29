const std = @import("std");

pub const Packet = packed struct(u344) {
    token: u32,
    transfer_len: u32 = wire_size,
    magic: u8,
    command: u8,
    command_size: u8 = 0,
    args: packed union {
        //256
        hash: u256,
        blank: packed struct(u256) { padding: u256 = 0 },
    } = .{ .blank = .{} },

    pub const Int = @typeInfo(Packet).@"struct".backing_integer.?;
    pub const wire_size = @bitSizeOf(Packet) / 8;
};

test "hash args round trip" {
    const hash: u256 = std.math.maxInt(u256) - 1;
    const packet: Packet = .{ .token = 1, .magic = 0xAF, .command = 0x21, .args = .{ .hash = hash } };

    var bytes: [Packet.wire_size]u8 = undefined;
    std.mem.writeInt(Packet.Int, &bytes, @bitCast(packet), .little);
    const decoded: Packet = @bitCast(std.mem.readInt(Packet.Int, &bytes, .little));

    try std.testing.expect(decoded.args.hash == hash);
    try std.testing.expect(decoded.transfer_len == Packet.wire_size);
}
