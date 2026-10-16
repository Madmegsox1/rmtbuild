const std = @import("std");
const net = @import("std").Io.net;
const Packet = @import("pack.zig").Packet;

pub const RmtInfo = struct {
    address: []const u8,
    port: u16,
};

pub const RmtCommands = enum(u8) {
    RMT_UP = 0x10,
    RMT_DOWN = 0x11,
};

pub const RmtHandler = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    info: RmtInfo,
    addr: net.IpAddress,
    token_c: u32 = 0,

    const Self = @This();

    pub fn init(alloc: std.mem.Allocator, io: std.Io, info: RmtInfo) !Self {
        const addr = try net.IpAddress.parse(info.address, info.port);

        return .{
            .allocator = alloc,
            .io = io,
            .info = info,
            .addr = addr,
        };
    }

    fn init_packet(self: *Self, command: RmtCommands) !Packet {
        if (self.token_c > std.math.maxInt(u32) - 1) {
            return error.PacketCOverflow;
        }
        self.token_c += 1;

        return .{
            .magic = 0xAF,
            .token = self.token_c,
            .command = @intFromEnum(command),
        };
    }

    fn pipe_packet(self: *Self, packet: Packet, stream: net.Stream) !void {
        var bytes: [27]u8 = undefined;
        var wbuff: [27]u8 = undefined;
        std.mem.writeInt(u216, &bytes, @bitCast(packet), .little);
        var writer = stream.writer(self.io, &wbuff);
        try writer.interface.writeAll(&bytes);
        const r = &writer.interface;
        try r.writeAll(&bytes);
        try r.flush();
    }

    pub fn up(self: *Self) !void {
        const stream = try self.addr.connect(self.io, .{ .mode = .stream });
        defer stream.close(std.testing.io);

        const packet = try self.init_packet(.RMT_UP);

        try pipe_packet(self, packet, stream);
    }
};

fn runRmt(rmt: *RmtHandler, err_out: *?anyerror) void {
    rmt.up() catch |err| {
        err_out.* = err;
    };
}

test "Does it work?" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const alloc = arena.allocator();

    const addr = try net.IpAddress.parse("0.0.0.0", 8099);
    var listen = try addr.listen(std.testing.io, .{ .kernel_backlog = 64, .mode = .stream, .protocol = .tcp });
    defer listen.deinit(std.testing.io);

    var rmt: RmtHandler = try RmtHandler.init(alloc, std.testing.io, .{ .address = "0.0.0.0", .port = 8099 });

    var rmt_err: ?anyerror = null;

    const thread = try std.Thread.spawn(.{}, runRmt, .{ &rmt, &rmt_err });

    var stream = try listen.accept(std.testing.io);
    defer stream.close(std.testing.io);

    var rbuff: [27]u8 = undefined;

    var reader = stream.reader(std.testing.io, &rbuff);
    //const bytes: []u8 = try reader.interface.take(27);

    const packet: Packet = @bitCast(try reader.interface.takeInt(u216, .little));
    thread.join();

    if (rmt_err) |e| return e;

    try std.testing.expect(packet.magic == 0xAF);
    try std.testing.expect(packet.command == @intFromEnum(RmtCommands.RMT_UP));
}
