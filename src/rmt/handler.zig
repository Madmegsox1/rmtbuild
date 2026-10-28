const std = @import("std");
const net = @import("std").Io.net;
const Packet = @import("pack.zig").Packet;
const FileHandler = @import("../file.zig").FileHandler;
const Serializer = @import("serializer.zig");

pub const RmtInfo = struct {
    address: []const u8,
    port: u16,
};

pub const RmtCommands = enum(u8) {
    RMT_UP = 0x10,
    RMT_DOWN = 0x11,
    RMT_LS = 0x20,
};

/// Files the server reported as changed. `files` slices into `payload`, free with `deinit`.
pub const ChangedFiles = struct {
    payload: Serializer.Bytes,
    files: std.ArrayList([]const u8),

    pub fn deinit(self: *ChangedFiles) void {
        self.files.deinit(self.payload.allocator);
        self.payload.deinit();
    }
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

    fn append_payload_len(packet: *Packet, payload_len: usize) void {
        packet.transfer_len += @intCast(payload_len);
    }

    fn pipe_packet(self: *Self, packet: Packet, stream: net.Stream) !void {
        try write_packet(self.io, packet, stream);
    }

    fn pipe_payload(self: *Self, payload: Serializer.Bytes, stream: net.Stream) !void {
        try write_payload(self.io, payload, stream);
    }

    /// Reads the server's reply and checks it answers `request`.
    fn read_reply(request: Packet, r: *std.Io.Reader) !Packet {
        const reply = try read_packet(r);

        if (reply.token != request.token) return error.TokenMismatch;
        if (reply.command != request.command) return error.CommandMismatch;

        return reply;
    }

    pub fn up(self: *Self) !void {
        const stream = try self.addr.connect(self.io, .{ .mode = .stream });
        defer stream.close(self.io);

        const packet = try self.init_packet(.RMT_UP);

        try pipe_packet(self, packet, stream);

        var rbuff: [27]u8 = undefined;
        var reader = stream.reader(self.io, &rbuff);
        _ = try read_reply(packet, &reader.interface);
    }

    /// Returns the files whose hashes differ from the server's, free with `deinit`.
    pub fn ls(self: *Self, file_handler: *FileHandler) !ChangedFiles {
        var serialized = try Serializer.string_map_to_bytes(u256, self.allocator, file_handler.hashed_files);
        defer serialized.deinit();

        const stream = try self.addr.connect(self.io, .{ .mode = .stream });
        defer stream.close(self.io);

        var packet = try self.init_packet(.RMT_LS);
        append_payload_len(&packet, serialized.bytes.len);

        try pipe_packet(self, packet, stream);
        try pipe_payload(self, serialized, stream);

        var rbuff: [1024]u8 = undefined;
        var reader = stream.reader(self.io, &rbuff);
        const r = &reader.interface;

        const reply = try read_reply(packet, r);
        const payload = try read_payload(self.allocator, reply, r);
        errdefer payload.deinit();

        return .{
            .payload = payload,
            .files = try Serializer.bytes_to_string_list(self.allocator, payload.bytes),
        };
    }
};

pub const RmtServer = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    file_handler: *FileHandler,

    const Self = @This();

    /// `file_handler` should already be hashed, it is the server side view of the files.
    pub fn init(alloc: std.mem.Allocator, io: std.Io, file_handler: *FileHandler) Self {
        return .{
            .allocator = alloc,
            .io = io,
            .file_handler = file_handler,
        };
    }

    /// Accepts connections forever, handling one packet per connection.
    pub fn serve(self: *Self, listener: *net.Server) !void {
        while (true) {
            const stream = try listener.accept(self.io);
            defer stream.close(self.io);

            self.handle(stream) catch |err| {
                std.log.err("rmt: failed to handle packet: {any}", .{err});
            };
        }
    }

    pub fn handle(self: *Self, stream: net.Stream) !void {
        var rbuff: [1024]u8 = undefined;
        var reader = stream.reader(self.io, &rbuff);
        const r = &reader.interface;

        const packet = try read_packet(r);

        const command = std.enums.fromInt(RmtCommands, packet.command) orelse return error.UnknownCommand;

        switch (command) {
            .RMT_UP => try self.handle_up(packet, stream),
            .RMT_LS => {
                const payload = try read_payload(self.allocator, packet, r);
                defer payload.deinit();
                try self.handle_ls(packet, payload.bytes, stream);
            },
            .RMT_DOWN => return error.UnsupportedCommand,
        }
    }

    fn reply_packet(request: Packet) Packet {
        return .{
            .magic = 0xAF,
            .token = request.token,
            .command = request.command,
        };
    }

    fn handle_up(self: *Self, request: Packet, stream: net.Stream) !void {
        try write_packet(self.io, reply_packet(request), stream);
    }

    fn handle_ls(self: *Self, request: Packet, payload: []const u8, stream: net.Stream) !void {
        var client_hashes = try Serializer.bytes_to_string_map(u256, self.allocator, payload);
        defer client_hashes.deinit();

        var changed: std.ArrayList([]const u8) = .empty;
        defer changed.deinit(self.allocator);

        try self.file_handler.source_git_files();
        try self.file_handler.hash_files();
        const server_hashes = self.file_handler.get_hashes();

        var it = client_hashes.iterator();
        while (it.next()) |entry| {
            const server_hash = server_hashes.get(entry.key_ptr.*);
            if (server_hash == null or server_hash.? != entry.value_ptr.*) {
                try changed.append(self.allocator, entry.key_ptr.*);
            }
        }

        var serialized = try Serializer.string_list_to_bytes(self.allocator, changed.items);
        defer serialized.deinit();

        var packet = reply_packet(request);
        RmtHandler.append_payload_len(&packet, serialized.bytes.len);

        try write_packet(self.io, packet, stream);
        try write_payload(self.io, serialized, stream);
    }
};

fn write_packet(io: std.Io, packet: Packet, stream: net.Stream) !void {
    var bytes: [27]u8 = undefined;
    var wbuff: [27]u8 = undefined;
    std.mem.writeInt(u216, &bytes, @bitCast(packet), .little);
    var writer = stream.writer(io, &wbuff);
    const w = &writer.interface;
    try w.writeAll(&bytes);
    try w.flush();
}

fn write_payload(io: std.Io, payload: Serializer.Bytes, stream: net.Stream) !void {
    var wbuff: [128]u8 = undefined;
    var writer = stream.writer(io, &wbuff);
    const w = &writer.interface;
    try w.writeAll(payload.bytes);
    try w.flush();
}

fn read_packet(r: *std.Io.Reader) !Packet {
    const packet: Packet = @bitCast(try r.takeInt(u216, .little));

    if (packet.magic != 0xAF) return error.InvalidMagic;
    if (packet.transfer_len < @sizeOf(Packet)) return error.InvalidTransferLen;

    return packet;
}

fn read_payload(alloc: std.mem.Allocator, packet: Packet, r: *std.Io.Reader) !Serializer.Bytes {
    return .init(alloc, try r.readAlloc(alloc, packet.transfer_len - @sizeOf(Packet)));
}

fn runRmt(rmt: *RmtHandler, err_out: *?anyerror) void {
    rmt.up() catch |err| {
        err_out.* = err;
    };
}

test "UP Command" {
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
    const packet = try read_packet(&reader.interface);

    try write_packet(std.testing.io, RmtServer.reply_packet(packet), stream);

    thread.join();

    if (rmt_err) |e| return e;

    try std.testing.expect(packet.magic == 0xAF);
    try std.testing.expect(packet.command == @intFromEnum(RmtCommands.RMT_UP));
}

fn runRmtLs(rmt: *RmtHandler, file: *FileHandler, out: *?ChangedFiles, err_out: *?anyerror) void {
    out.* = rmt.ls(file) catch |err| {
        err_out.* = err;
        return;
    };
}

test "LS Command" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const alloc = arena.allocator();

    const addr = try net.IpAddress.parse("0.0.0.0", 8099);
    var listen = try addr.listen(std.testing.io, .{ .kernel_backlog = 64, .mode = .stream, .protocol = .tcp });
    defer listen.deinit(std.testing.io);

    var rmt: RmtHandler = try RmtHandler.init(alloc, std.testing.io, .{ .address = "0.0.0.0", .port = 8099 });

    var rmt_err: ?anyerror = null;

    var file: FileHandler = .init(std.testing.allocator, std.testing.io);
    defer file.deinit();

    try file.source_git_files();
    try file.hash_files();

    var changed: ?ChangedFiles = null;

    const thread = try std.Thread.spawn(.{}, runRmtLs, .{ &rmt, &file, &changed, &rmt_err });

    var stream = try listen.accept(std.testing.io);
    defer stream.close(std.testing.io);

    var rbuff: [27]u8 = undefined;

    var reader = stream.reader(std.testing.io, &rbuff);

    const packet = try read_packet(&reader.interface);

    const payload = try read_payload(alloc, packet, &reader.interface);

    var map = try Serializer.bytes_to_string_map(u256, std.testing.allocator, payload.bytes);
    defer map.deinit();

    const reply_files = try Serializer.string_list_to_bytes(alloc, &.{"build.zig"});
    var reply = RmtServer.reply_packet(packet);
    RmtHandler.append_payload_len(&reply, reply_files.bytes.len);
    try write_packet(std.testing.io, reply, stream);
    try write_payload(std.testing.io, reply_files, stream);

    thread.join();

    if (rmt_err) |e| return e;

    try std.testing.expect(changed.?.files.items.len == 1);
    try std.testing.expectEqualStrings("build.zig", changed.?.files.items[0]);

    try std.testing.expect(packet.magic == 0xAF);
    try std.testing.expect(packet.command == @intFromEnum(RmtCommands.RMT_LS));

    const test_hash = file.get_hashes().get("test.txt").?;
    const test_hash_rmt = map.get("test.txt").?;

    try std.testing.expect(test_hash == test_hash_rmt);
}

fn runServerOnce(server: *RmtServer, listen: *net.Server, err_out: *?anyerror) void {
    const stream = listen.accept(server.io) catch |err| {
        err_out.* = err;
        return;
    };
    defer stream.close(server.io);

    server.handle(stream) catch |err| {
        err_out.* = err;
    };
}

test "Server UP Command" {
    const addr = try net.IpAddress.parse("127.0.0.1", 8100);
    var listen = try addr.listen(std.testing.io, .{ .kernel_backlog = 64, .mode = .stream, .protocol = .tcp, .reuse_address = true });
    defer listen.deinit(std.testing.io);

    var file: FileHandler = .init(std.testing.allocator, std.testing.io);
    defer file.deinit();

    var server: RmtServer = .init(std.testing.allocator, std.testing.io, &file);
    var server_err: ?anyerror = null;

    const thread = try std.Thread.spawn(.{}, runServerOnce, .{ &server, &listen, &server_err });

    const stream = try addr.connect(std.testing.io, .{ .mode = .stream });
    defer stream.close(std.testing.io);

    try write_packet(std.testing.io, .{ .magic = 0xAF, .token = 42, .command = @intFromEnum(RmtCommands.RMT_UP) }, stream);

    var rbuff: [27]u8 = undefined;
    var reader = stream.reader(std.testing.io, &rbuff);
    const reply = try read_packet(&reader.interface);

    thread.join();

    if (server_err) |e| return e;

    try std.testing.expect(reply.magic == 0xAF);
    try std.testing.expect(reply.token == 42);
    try std.testing.expect(reply.command == @intFromEnum(RmtCommands.RMT_UP));
}

test "Server LS Command" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const alloc = arena.allocator();

    const addr = try net.IpAddress.parse("127.0.0.1", 8101);
    var listen = try addr.listen(std.testing.io, .{ .kernel_backlog = 64, .mode = .stream, .protocol = .tcp, .reuse_address = true });
    defer listen.deinit(std.testing.io);

    var file: FileHandler = .init(std.testing.allocator, std.testing.io);
    defer file.deinit();

    try file.source_git_files();
    try file.hash_files();

    var server: RmtServer = .init(std.testing.allocator, std.testing.io, &file);
    var server_err: ?anyerror = null;

    // Client view: test.txt matches, build.zig differs, missing.txt doesn't exist on the server.
    var client_hashes = std.StringHashMap(u256).init(alloc);
    try client_hashes.put("test.txt", file.get_hashes().get("test.txt").?);
    try client_hashes.put("build.zig", 0);
    try client_hashes.put("missing.txt", 1234);

    const serialized = try Serializer.string_map_to_bytes(u256, alloc, client_hashes);

    const thread = try std.Thread.spawn(.{}, runServerOnce, .{ &server, &listen, &server_err });

    const stream = try addr.connect(std.testing.io, .{ .mode = .stream });
    defer stream.close(std.testing.io);

    var packet: Packet = .{ .magic = 0xAF, .token = 7, .command = @intFromEnum(RmtCommands.RMT_LS) };
    RmtHandler.append_payload_len(&packet, serialized.bytes.len);
    try write_packet(std.testing.io, packet, stream);
    try write_payload(std.testing.io, serialized, stream);

    var rbuff: [256]u8 = undefined;
    var reader = stream.reader(std.testing.io, &rbuff);
    const reply = try read_packet(&reader.interface);
    const payload = try read_payload(alloc, reply, &reader.interface);

    thread.join();

    if (server_err) |e| return e;

    try std.testing.expect(reply.magic == 0xAF);
    try std.testing.expect(reply.token == 7);
    try std.testing.expect(reply.command == @intFromEnum(RmtCommands.RMT_LS));

    const changed = try Serializer.bytes_to_string_list(alloc, payload.bytes);

    try std.testing.expect(changed.items.len == 2);
    for (changed.items) |name| {
        try std.testing.expect(std.mem.eql(u8, name, "build.zig") or std.mem.eql(u8, name, "missing.txt"));
    }
}
