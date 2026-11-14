const std = @import("std");
const net = @import("std").Io.net;
const Packet = @import("pack.zig").Packet;
const RunKind = @import("pack.zig").RunKind;
const FileHandler = @import("../file.zig").FileHandler;
const config = @import("../config.zig");
const Serializer = @import("serializer.zig");
const wire = @import("wire.zig");
const auth = @import("auth.zig");
const forward = @import("forward.zig");
const process = @import("../process.zig");
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const RmtInfo = struct {
    address: []const u8,
    port: u16,
    key: auth.Key,
};

pub const RmtCommands = enum(u8) {
    RMT_UP = 0x10,
    RMT_DOWN = 0x11,
    RMT_LS = 0x20,
    RMT_FR = 0x21,
    RMT_FN = 0x22,
    RMT_FD = 0x23,
    RMT_RUN = 0x30,
    RMT_FWD = 0x31,
};

pub const SyncStats = struct {
    created: usize = 0,
    replaced: usize = 0,
    deleted: usize = 0,
};

pub const RunResult = union(enum) {
    exited: u32,
    signal: u32,
    /// The server couldn't run the command. Message is owned by the handler's allocator.
    failed: []u8,
};

pub const LsResult = struct {
    payload: Serializer.Bytes,
    missing: std.ArrayList([]const u8),
    changed: std.StringHashMap(u256),
    extra: std.StringHashMap(u256),

    pub fn deinit(self: *LsResult) void {
        self.missing.deinit(self.payload.allocator);
        self.changed.deinit();
        self.extra.deinit();
        self.payload.deinit();
    }

    /// Wire format: a string list of three sections, `[missing list][changed map][extra map]`.
    pub fn encode(
        alloc: std.mem.Allocator,
        missing: []const []const u8,
        changed: std.StringHashMap(u256),
        extra: std.StringHashMap(u256),
    ) !Serializer.Bytes {
        const missing_bytes = try Serializer.string_list_to_bytes(alloc, missing);
        defer missing_bytes.deinit();
        const changed_bytes = try Serializer.string_map_to_bytes(u256, alloc, changed);
        defer changed_bytes.deinit();
        const extra_bytes = try Serializer.string_map_to_bytes(u256, alloc, extra);
        defer extra_bytes.deinit();

        return Serializer.string_list_to_bytes(alloc, &.{ missing_bytes.bytes, changed_bytes.bytes, extra_bytes.bytes });
    }

    /// Takes ownership of `payload` on success.
    pub fn decode(payload: Serializer.Bytes) !LsResult {
        const alloc = payload.allocator;

        var sections = try Serializer.bytes_to_string_list(alloc, payload.bytes);
        defer sections.deinit(alloc);
        if (sections.items.len != 3) return error.InvalidReply;

        var missing = try Serializer.bytes_to_string_list(alloc, sections.items[0]);
        errdefer missing.deinit(alloc);
        var changed = try Serializer.bytes_to_string_map(u256, alloc, sections.items[1]);
        errdefer changed.deinit();
        const extra = try Serializer.bytes_to_string_map(u256, alloc, sections.items[2]);

        return .{ .payload = payload, .missing = missing, .changed = changed, .extra = extra };
    }
};

pub const RmtHandler = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    info: RmtInfo,
    addr: net.IpAddress,
    /// Atomic, forwarded connections make requests from their own threads.
    token_c: std.atomic.Value(u32) = .init(0),

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
        const token = self.token_c.fetchAdd(1, .monotonic) +% 1;
        if (token == 0) return error.PacketCOverflow;

        return .{
            .magic = wire.magic,
            .token = token,
            .command = @intFromEnum(command),
        };
    }

    fn connect(self: *Self) !net.Stream {
        const stream = try self.addr.connect(self.io, .{ .mode = .stream });
        errdefer stream.close(self.io);
        try auth.client_handshake(self.io, &self.info.key, stream);
        return stream;
    }

    fn pipe_packet(self: *Self, packet: Packet, stream: net.Stream) !void {
        try wire.write_packet(self.io, packet, stream);
    }

    fn pipe_payload(self: *Self, payload: []const u8, stream: net.Stream) !void {
        try wire.write_payload(self.io, payload, stream);
    }

    /// Reads the server's reply and checks it answers `request`.
    fn read_reply(request: Packet, r: *std.Io.Reader) !Packet {
        const reply = try wire.read_packet(r);

        if (reply.token != request.token) return error.TokenMismatch;
        if (reply.command != request.command) return error.CommandMismatch;

        return reply;
    }

    pub fn up(self: *Self) !void {
        const stream = try self.connect();
        defer stream.close(self.io);

        const packet = try self.init_packet(.RMT_UP);

        try pipe_packet(self, packet, stream);

        var rbuff: [Packet.wire_size]u8 = undefined;
        var reader = stream.reader(self.io, &rbuff);
        _ = try read_reply(packet, &reader.interface);
    }

    pub fn fr(self: *Self, file: []const u8, file_name: []const u8, remote_hash: u256, local_hash: u256) !void {
        var payload = try Serializer.file_payload_to_bytes(self.allocator, file_name, file);
        defer payload.deinit();

        var packet = try self.init_packet(.RMT_FR);
        packet.args.hash = remote_hash;
        try wire.append_payload_len(&packet, payload.bytes.len);

        const stream = try self.connect();
        defer stream.close(self.io);

        try pipe_packet(self, packet, stream);
        try pipe_payload(self, payload.bytes, stream);

        var rbuff: [Packet.wire_size]u8 = undefined;
        var reader = stream.reader(self.io, &rbuff);
        const reply = try read_reply(packet, &reader.interface);
        if (reply.args.hash != local_hash) {
            return error.MismatchedHash;
        }
    }

    pub fn fnp(self: *Self, file: []const u8, file_name: []const u8, expected_hash: u256) !void {
        var payload = try Serializer.file_payload_to_bytes(self.allocator, file_name, file);
        defer payload.deinit();

        var packet = try self.init_packet(.RMT_FN);
        packet.args.hash = expected_hash;
        try wire.append_payload_len(&packet, payload.bytes.len);

        const stream = try self.connect();
        defer stream.close(self.io);

        try pipe_packet(self, packet, stream);
        try pipe_payload(self, payload.bytes, stream);

        var rbuff: [Packet.wire_size]u8 = undefined;
        var reader = stream.reader(self.io, &rbuff);
        const reply = try read_reply(packet, &reader.interface);
        if (reply.args.hash != expected_hash) {
            return error.MismatchedHash;
        }
    }

    pub fn fd(self: *Self, file_name: []const u8, remote_hash: u256) !void {
        var packet = try self.init_packet(.RMT_FD);
        packet.args.hash = remote_hash;
        try wire.append_payload_len(&packet, file_name.len);

        const stream = try self.connect();
        defer stream.close(self.io);

        try pipe_packet(self, packet, stream);
        try pipe_payload(self, file_name, stream);

        var rbuff: [Packet.wire_size]u8 = undefined;
        var reader = stream.reader(self.io, &rbuff);
        _ = try read_reply(packet, &reader.interface);
    }

    pub fn ls(self: *Self, file_handler: *FileHandler) !LsResult {
        var serialized = try Serializer.string_map_to_bytes(u256, self.allocator, file_handler.hashed_files);
        defer serialized.deinit();

        const stream = try self.connect();
        defer stream.close(self.io);

        var packet = try self.init_packet(.RMT_LS);
        try wire.append_payload_len(&packet, serialized.bytes.len);

        try pipe_packet(self, packet, stream);
        try pipe_payload(self, serialized.bytes, stream);

        var rbuff: [1024]u8 = undefined;
        var reader = stream.reader(self.io, &rbuff);
        const r = &reader.interface;

        const reply = try read_reply(packet, r);
        const payload = try wire.read_payload(self.allocator, reply, r);
        errdefer payload.deinit();

        return LsResult.decode(payload);
    }

    /// Makes the server's files match `file_handler`, which should already be hashed.
    pub fn sync(self: *Self, file_handler: *FileHandler) !SyncStats {
        var diff = try self.ls(file_handler);
        defer diff.deinit();

        var stats: SyncStats = .{};

        for (diff.missing.items) |name| {
            const data = try file_handler.read_file(self.allocator, name);
            defer self.allocator.free(data);
            try self.fnp(data, name, file_handler.get_hashes().get(name).?);
            stats.created += 1;
        }

        var changed = diff.changed.iterator();
        while (changed.next()) |entry| {
            const name = entry.key_ptr.*;
            const data = try file_handler.read_file(self.allocator, name);
            defer self.allocator.free(data);
            try self.fr(data, name, entry.value_ptr.*, file_handler.get_hashes().get(name).?);
            stats.replaced += 1;
        }

        var extra = diff.extra.iterator();
        while (extra.next()) |entry| {
            try self.fd(entry.key_ptr.*, entry.value_ptr.*);
            stats.deleted += 1;
        }

        return stats;
    }

    /// Runs the configured command `name` on the server, writing its output to `out` as it arrives.
    pub fn run(self: *Self, name: []const u8, out: *std.Io.Writer) !RunResult {
        var packet = try self.init_packet(.RMT_RUN);
        try wire.append_payload_len(&packet, name.len);

        const stream = try self.connect();
        defer stream.close(self.io);

        try pipe_packet(self, packet, stream);
        try pipe_payload(self, name, stream);

        var rbuff: [4096]u8 = undefined;
        var reader = stream.reader(self.io, &rbuff);
        const r = &reader.interface;

        while (true) {
            const reply = try read_reply(packet, r);
            const payload = try wire.read_payload(self.allocator, reply, r);
            errdefer payload.deinit();

            switch (reply.args.run.kind) {
                .output => {
                    defer payload.deinit();
                    try out.writeAll(payload.bytes);
                    try out.flush();
                },
                .exit => {
                    payload.deinit();
                    return .{ .exited = reply.args.run.code };
                },
                .signal => {
                    payload.deinit();
                    return .{ .signal = reply.args.run.code };
                },
                .failed => return .{ .failed = payload.bytes },
                _ => return error.InvalidReply,
            }
        }
    }

    /// Opens a connection to `port` on the server's localhost. Afterwards the stream carries
    /// raw bytes. `error.ForwardRefused` if nothing is listening there.
    pub fn open_forward(self: *Self, port: u16) !net.Stream {
        const stream = try self.connect();
        errdefer stream.close(self.io);

        var packet = try self.init_packet(.RMT_FWD);
        packet.args = .{ .forward = .{ .port = port } };
        try pipe_packet(self, packet, stream);

        // Exactly one header, so the target's first bytes (if it talks first) aren't buffered here.
        var rbuff: [Packet.wire_size]u8 = undefined;
        var reader = stream.reader(self.io, &rbuff);
        const reply = try read_reply(packet, &reader.interface);
        if (!reply.args.forward.ok) return error.ForwardRefused;

        return stream;
    }

    /// Listens on 127.0.0.1:`fwd.local` and tunnels each connection to the server's
    /// localhost:`fwd.remote`. Runs until `Forwarder.stop`.
    pub fn forward(self: *Self, fwd: config.Forward) !*Forwarder {
        const addr = try net.IpAddress.parse("127.0.0.1", fwd.local);
        var listener = try addr.listen(self.io, .{ .mode = .stream, .protocol = .tcp, .reuse_address = true });
        errdefer listener.deinit(self.io);

        const forwarder = try self.allocator.create(Forwarder);
        errdefer self.allocator.destroy(forwarder);
        forwarder.* = .{ .rmt = self, .listener = listener, .fwd = fwd, .thread = undefined };
        forwarder.thread = try std.Thread.spawn(.{}, Forwarder.accept_loop, .{forwarder});

        return forwarder;
    }
};

pub const Forwarder = struct {
    rmt: *RmtHandler,
    listener: net.Server,
    fwd: config.Forward,
    thread: std.Thread,
    stopping: std.atomic.Value(bool) = .init(false),

    /// Stops accepting, connections already being forwarded carry on until they close.
    pub fn stop(self: *Forwarder) void {
        const io = self.rmt.io;
        self.stopping.store(true, .release);
        // accept() can't be interrupted portably, so wake it with a connection of our own.
        if (net.IpAddress.parse("127.0.0.1", self.fwd.local)) |addr| {
            if (addr.connect(io, .{ .mode = .stream })) |s| s.close(io) else |_| {}
        } else |_| {}
        self.thread.join();
        self.listener.deinit(io);
        self.rmt.allocator.destroy(self);
    }

    fn accept_loop(self: *Forwarder) void {
        const io = self.rmt.io;
        while (true) {
            const local = self.listener.accept(io) catch |err| {
                std.log.err("forward localhost:{d}: {s}", .{ self.fwd.local, @errorName(err) });
                return;
            };
            if (self.stopping.load(.acquire)) {
                local.close(io);
                return;
            }
            const thread = std.Thread.spawn(.{}, connection, .{ self.rmt, local, self.fwd }) catch {
                local.close(io);
                continue;
            };
            thread.detach();
        }
    }

    fn connection(rmt: *RmtHandler, local: net.Stream, fwd: config.Forward) void {
        const io = rmt.io;
        defer local.close(io);

        const remote = rmt.open_forward(fwd.remote) catch |err| {
            switch (err) {
                error.ForwardRefused => std.log.warn("forward localhost:{d}: nothing is listening on the server's port {d} yet", .{ fwd.local, fwd.remote }),
                else => std.log.warn("forward localhost:{d}: {s}", .{ fwd.local, @errorName(err) }),
            }
            return;
        };
        defer remote.close(io);

        var buf: [16 * 1024]u8 = undefined;
        var reader = local.reader(io, &buf);
        forward.pipe(io, local, &reader.interface, remote);
    }
};

pub const RmtServer = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    file_handler: *FileHandler,
    key: auth.Key,
    /// Requests with a bigger payload are dropped before anything is allocated.
    max_payload: u32 = default_max_payload,
    /// Connections run on their own threads, file changes and config reads go one at a time.
    files_lock: std.Io.Mutex = .init,

    pub const default_max_payload = 256 * 1024 * 1024;

    const Self = @This();

    /// `file_handler` should already be hashed, it is the server side view of the files.
    pub fn init(alloc: std.mem.Allocator, io: std.Io, file_handler: *FileHandler, key: auth.Key) Self {
        return .{
            .allocator = alloc,
            .io = io,
            .file_handler = file_handler,
            .key = key,
        };
    }

    /// Accepts connections forever, each on its own thread so a long running command doesn't
    /// block syncs or forwarded connections. One packet per connection.
    pub fn serve(self: *Self, listener: *net.Server) !void {
        while (true) {
            const stream = try listener.accept(self.io);
            const thread = std.Thread.spawn(.{}, handle_connection, .{ self, stream }) catch |err| {
                std.log.err("rmt: can't start a thread for a connection: {s}", .{@errorName(err)});
                stream.close(self.io);
                continue;
            };
            thread.detach();
        }
    }

    fn handle_connection(self: *Self, stream: net.Stream) void {
        defer stream.close(self.io);
        self.handle(stream) catch |err| switch (err) {
            error.AuthFailed => std.log.warn("rmt: rejected connection with the wrong key", .{}),
            else => std.log.err("rmt: failed to handle packet: {any}", .{err}),
        };
    }

    pub fn handle(self: *Self, stream: net.Stream) !void {
        try auth.server_handshake(self.io, &self.key, stream);

        var rbuff: [1024]u8 = undefined;
        var reader = stream.reader(self.io, &rbuff);
        const r = &reader.interface;

        const packet = try wire.read_packet(r);

        const command = std.enums.fromInt(RmtCommands, packet.command) orelse return error.UnknownCommand;

        switch (command) {
            .RMT_UP => try self.handle_up(packet, stream),
            .RMT_LS => {
                const payload = try self.read_payload(packet, r);
                defer payload.deinit();
                self.files_lock.lockUncancelable(self.io);
                defer self.files_lock.unlock(self.io);
                try self.handle_ls(packet, payload.bytes, stream);
            },
            .RMT_FR => {
                const payload = try self.read_payload(packet, r);
                defer payload.deinit();
                self.files_lock.lockUncancelable(self.io);
                defer self.files_lock.unlock(self.io);
                try self.handle_fr(packet, payload.bytes, stream);
            },
            .RMT_FN => {
                const payload = try self.read_payload(packet, r);
                defer payload.deinit();
                self.files_lock.lockUncancelable(self.io);
                defer self.files_lock.unlock(self.io);
                try self.handle_fn(packet, payload.bytes, stream);
            },
            .RMT_FD => {
                const payload = try self.read_payload(packet, r);
                defer payload.deinit();
                self.files_lock.lockUncancelable(self.io);
                defer self.files_lock.unlock(self.io);
                try self.handle_fd(packet, payload.bytes, stream);
            },
            .RMT_RUN => {
                const payload = try self.read_payload(packet, r);
                defer payload.deinit();
                try self.handle_run(packet, payload.bytes, stream);
            },
            .RMT_FWD => try self.handle_forward(packet, r, stream),
            .RMT_DOWN => return error.UnsupportedCommand,
        }
    }

    fn read_payload(self: *Self, packet: Packet, r: *std.Io.Reader) !Serializer.Bytes {
        if (packet.transfer_len - Packet.wire_size > self.max_payload) return error.PayloadTooLarge;
        return wire.read_payload(self.allocator, packet, r);
    }

    fn handle_up(self: *Self, request: Packet, stream: net.Stream) !void {
        try wire.write_packet(self.io, wire.reply_packet(request), stream);
    }

    fn handle_fr(self: *Self, request: Packet, payload: []const u8, stream: net.Stream) !void {
        const file = try Serializer.bytes_to_file_payload(payload);

        const new_hash = try self.file_handler.replace_file(file.name, request.args.hash, file.data);

        var packet = wire.reply_packet(request);
        packet.args.hash = new_hash;
        try wire.write_packet(self.io, packet, stream);
    }

    fn handle_fd(self: *Self, request: Packet, payload: []const u8, stream: net.Stream) !void {
        try self.file_handler.delete_file(payload, request.args.hash);

        var packet = wire.reply_packet(request);
        packet.args.hash = request.args.hash;
        try wire.write_packet(self.io, packet, stream);
    }

    /// Looks `name` up in the server's own (synced) rmtbuild.yaml, so only configured commands run.
    /// Streams output packets, then ends with exit / signal / failed.
    fn handle_run(self: *Self, request: Packet, name: []const u8, stream: net.Stream) !void {
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const alloc = arena.allocator();

        var diag: config.Diagnostic = .{};
        const loaded = blk: {
            self.files_lock.lockUncancelable(self.io);
            defer self.files_lock.unlock(self.io);
            break :blk config.Config.load(alloc, self.io, self.file_handler.root, &diag);
        };
        const cfg = loaded catch |err| switch (err) {
            error.FileNotFound => return self.run_failed(request, stream, "server has no " ++ config.file_name ++ ", is it tracked by git?", .{}),
            error.InvalidConfig => return self.run_failed(request, stream, "server's " ++ config.file_name ++ " is invalid: {f}", .{diag}),
            else => return self.run_failed(request, stream, "can't read server's " ++ config.file_name ++ ": {s}", .{@errorName(err)}),
        };

        const command = cfg.commands.get(name) orelse
            return self.run_failed(request, stream, "unknown command '{s}' in server's " ++ config.file_name, .{name});

        var running = process.spawn(self.io, self.allocator, self.file_handler.root, self.file_handler.child_cwd(), command.run) catch |err|
            return self.run_failed(request, stream, "failed to start '{s}': {s}", .{ name, @errorName(err) });
        defer running.deinit();

        // Long running commands (servers) may print nothing for ages, so a dropped client is
        // noticed by watching the connection rather than by the next failed write.
        var watch: RunWatch = .{ .io = self.io, .stream = stream, .running = &running };
        const watcher = try std.Thread.spawn(.{}, RunWatch.run, .{&watch});
        defer {
            watch.finished.store(true, .release);
            // Wakes the watcher's read once the reply is out.
            stream.shutdown(self.io, .both) catch {};
            watcher.join();
        }

        var client_gone = false;
        var buf: [4096]u8 = undefined;
        while (true) {
            const n = running.output().readStreaming(self.io, &.{&buf}) catch |err| switch (err) {
                error.EndOfStream => break,
                else => return err,
            };
            if (n == 0) break;
            // Keep draining so the command never blocks on a full pipe while it's being stopped.
            if (client_gone) continue;

            self.send_output(request, buf[0..n], stream) catch {
                client_gone = true;
                running.stop();
            };
        }

        const exit = try running.wait();
        watch.finished.store(true, .release);
        if (client_gone or watch.disconnected.load(.acquire)) {
            std.log.info("rmt: client disconnected, stopped '{s}'", .{name});
            return;
        }

        var packet = wire.reply_packet(request);
        packet.args = switch (exit) {
            .exited => |code| .{ .run = .{ .kind = .exit, .code = code } },
            .signal => |sig| .{ .run = .{ .kind = .signal, .code = sig } },
            .unknown => |status| return self.run_failed(request, stream, "'{s}' ended with unknown status {d}", .{ name, status }),
        };
        try wire.write_packet(self.io, packet, stream);
    }

    fn send_output(self: *Self, request: Packet, data: []const u8, stream: net.Stream) !void {
        var packet = wire.reply_packet(request);
        packet.args = .{ .run = .{ .kind = .output } };
        try wire.append_payload_len(&packet, data.len);
        try wire.write_packet(self.io, packet, stream);
        try wire.write_payload(self.io, data, stream);
    }

    /// Connects to `port` on the server's own localhost and pipes bytes until both sides close.
    /// Only localhost, so the server can't be used to reach other machines on its network.
    fn handle_forward(self: *Self, request: Packet, r: *std.Io.Reader, stream: net.Stream) !void {
        const port = request.args.forward.port;
        var packet = wire.reply_packet(request);
        packet.args = .{ .forward = .{ .port = port } };

        const target = connect_localhost(self.io, port) catch |err| {
            std.log.info("rmt: forward to port {d} refused: {s}", .{ port, @errorName(err) });
            return wire.write_packet(self.io, packet, stream);
        };
        defer target.close(self.io);

        packet.args.forward.ok = true;
        try wire.write_packet(self.io, packet, stream);
        forward.pipe(self.io, stream, r, target);
    }

    fn run_failed(self: *Self, request: Packet, stream: net.Stream, comptime fmt: []const u8, args: anytype) !void {
        const message = try std.fmt.allocPrint(self.allocator, fmt, args);
        defer self.allocator.free(message);
        std.log.info("rmt: run: {s}", .{message});

        var packet = wire.reply_packet(request);
        packet.args = .{ .run = .{ .kind = .failed } };
        try wire.append_payload_len(&packet, message.len);
        try wire.write_packet(self.io, packet, stream);
        try wire.write_payload(self.io, message, stream);
    }

    fn handle_fn(self: *Self, request: Packet, payload: []const u8, stream: net.Stream) !void {
        const file = try Serializer.bytes_to_file_payload(payload);

        // Check before touching the disk so a bad transfer never leaves a file behind.
        var hash: [32]u8 = undefined;
        Sha256.hash(file.data, &hash, .{});
        if (std.mem.readInt(u256, &hash, .little) != request.args.hash) {
            return error.HashMismatch;
        }

        const new_hash = try self.file_handler.create_file(file.name, file.data);

        var packet = wire.reply_packet(request);
        packet.args.hash = new_hash;
        try wire.write_packet(self.io, packet, stream);
    }

    fn handle_ls(self: *Self, request: Packet, payload: []const u8, stream: net.Stream) !void {
        var client_hashes = try Serializer.bytes_to_string_map(u256, self.allocator, payload);
        defer client_hashes.deinit();

        var missing: std.ArrayList([]const u8) = .empty;
        defer missing.deinit(self.allocator);
        var changed = std.StringHashMap(u256).init(self.allocator);
        defer changed.deinit();
        var extra = std.StringHashMap(u256).init(self.allocator);
        defer extra.deinit();

        try self.file_handler.source_git_files();
        try self.file_handler.hash_files();
        const server_hashes = self.file_handler.get_hashes();

        var client_it = client_hashes.iterator();
        while (client_it.next()) |entry| {
            if (server_hashes.get(entry.key_ptr.*)) |server_hash| {
                if (server_hash != entry.value_ptr.*) try changed.put(entry.key_ptr.*, server_hash);
            } else {
                try missing.append(self.allocator, entry.key_ptr.*);
            }
        }

        var server_it = server_hashes.iterator();
        while (server_it.next()) |entry| {
            if (!client_hashes.contains(entry.key_ptr.*)) try extra.put(entry.key_ptr.*, entry.value_ptr.*);
        }

        var serialized = try LsResult.encode(self.allocator, missing.items, changed, extra);
        defer serialized.deinit();

        var packet = wire.reply_packet(request);
        try wire.append_payload_len(&packet, serialized.bytes.len);

        try wire.write_packet(self.io, packet, stream);
        try wire.write_payload(self.io, serialized.bytes, stream);
    }
};

/// Watches a RUN connection: the client sends nothing after its request, so any end of stream
/// means it went away, and the command is stopped.
const RunWatch = struct {
    io: std.Io,
    stream: net.Stream,
    running: *const process.Running,
    finished: std.atomic.Value(bool) = .init(false),
    disconnected: std.atomic.Value(bool) = .init(false),

    fn run(self: *RunWatch) void {
        var buf: [64]u8 = undefined;
        var reader = self.stream.reader(self.io, &buf);
        while (true) {
            reader.interface.fillMore() catch break;
            reader.interface.tossBuffered();
        }
        if (self.finished.load(.acquire)) return;

        self.disconnected.store(true, .release);
        self.running.stop();

        // Give it a few seconds to shut down cleanly before forcing it.
        for (0..50) |_| {
            if (self.finished.load(.acquire)) return;
            self.io.sleep(.fromMilliseconds(100), .awake) catch return;
        }
        self.running.kill();
    }
};

/// Makes `rmtbuild serve` stop running commands before it exits.
pub const stop_commands_on_exit = process.stop_all_on_exit;

fn connect_localhost(io: std.Io, port: u16) !net.Stream {
    // Servers often bind only one of the two loopback addresses.
    const v4 = try net.IpAddress.parse("127.0.0.1", port);
    return v4.connect(io, .{ .mode = .stream }) catch {
        const v6 = try net.IpAddress.parse("::1", port);
        return v6.connect(io, .{ .mode = .stream });
    };
}
