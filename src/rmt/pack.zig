const std = @import("std");

pub const Packet = packed struct(u216) {
    token: u32,
    transfer_len: u32 = @sizeOf(Packet),
    magic: u8,
    command: u8,
    command_size: u8 = 0,
    args: packed union {
        //128
        raw: u128,
        blank: packed struct(u128) { padding: u128 = 0 },
    } = .{ .blank = .{} },
};
