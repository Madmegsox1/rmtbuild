const std = @import("std");

pub const Packet = packed struct(u336) {
    token: u32,
    transfer_len: u32 = wire_size,
    magic: u8,
    command: u8,
    args: packed union {
        //256
        hash: u256,
        run: RunArgs,
        forward: ForwardArgs,
        blank: packed struct(u256) { padding: u256 = 0 },
    } = .{ .blank = .{} },

    pub const Int = @typeInfo(Packet).@"struct".backing_integer.?;
    pub const wire_size = @bitSizeOf(Packet) / 8;
};

/// What an RMT_RUN reply packet carries. The server sends any number of `output` packets,
/// then exactly one of `exit`, `signal` or `failed`.
pub const RunKind = enum(u8) {
    /// Payload is a chunk of the command's output (stdout and stderr interleaved).
    output = 0,
    /// The command exited, `code` is its exit status.
    exit = 1,
    /// The command was killed, `code` is the signal number.
    signal = 2,
    /// The server couldn't run the command, payload is the reason.
    failed = 3,
    /// Payload is a debug-session notice (`mode=...` lines). Not part of the command's output.
    notice = 4,
    _,
};

/// RMT_FWD request: `port` on the server's localhost to connect to.
/// Reply: same port, `ok` if the server connected. After an ok reply the connection carries raw
/// bytes in both directions.
pub const ForwardArgs = packed struct(u256) {
    port: u16,
    ok: bool = false,
    padding: u239 = 0,
};

pub const RunArgs = packed struct(u256) {
    kind: RunKind,
    code: u32 = 0,
    padding: u216 = 0,
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

test "run args round trip" {
    const packet: Packet = .{ .token = 3, .magic = 0xAF, .command = 0x30, .args = .{ .run = .{ .kind = .exit, .code = 42 } } };

    var bytes: [Packet.wire_size]u8 = undefined;
    std.mem.writeInt(Packet.Int, &bytes, @bitCast(packet), .little);
    const decoded: Packet = @bitCast(std.mem.readInt(Packet.Int, &bytes, .little));

    try std.testing.expect(decoded.args.run.kind == .exit);
    try std.testing.expect(decoded.args.run.code == 42);
}
