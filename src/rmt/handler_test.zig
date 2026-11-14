const std = @import("std");
const builtin = @import("builtin");
const is_windows = builtin.os.tag == .windows;
const net = std.Io.net;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Packet = @import("pack.zig").Packet;
const Serializer = @import("serializer.zig");
const wire = @import("wire.zig");
const handler = @import("handler.zig");
const RmtHandler = handler.RmtHandler;
const RmtServer = handler.RmtServer;
const RmtCommands = handler.RmtCommands;
const LsResult = handler.LsResult;
const FileHandler = @import("../file.zig").FileHandler;
const TestRepo = @import("../file.zig").TestRepo;
const auth = @import("auth.zig");

const test_key: auth.Key = [_]u8{0x42} ** auth.key_len;

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
    var listen = try addr.listen(std.testing.io, .{ .kernel_backlog = 64, .mode = .stream, .protocol = .tcp, .reuse_address = true });
    defer listen.deinit(std.testing.io);

    var rmt: RmtHandler = try RmtHandler.init(alloc, std.testing.io, .{ .address = "0.0.0.0", .port = 8099, .key = test_key });

    var rmt_err: ?anyerror = null;

    const thread = try std.Thread.spawn(.{}, runRmt, .{ &rmt, &rmt_err });

    var stream = try listen.accept(std.testing.io);
    defer stream.close(std.testing.io);
    try auth.server_handshake(std.testing.io, &test_key, stream);

    var rbuff: [Packet.wire_size]u8 = undefined;

    var reader = stream.reader(std.testing.io, &rbuff);
    const packet = try wire.read_packet(&reader.interface);

    try wire.write_packet(std.testing.io, wire.reply_packet(packet), stream);

    thread.join();

    if (rmt_err) |e| return e;

    try std.testing.expect(packet.magic == 0xAF);
    try std.testing.expect(packet.command == @intFromEnum(RmtCommands.RMT_UP));
}

fn runRmtLs(rmt: *RmtHandler, file: *FileHandler, out: *?LsResult, err_out: *?anyerror) void {
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
    var listen = try addr.listen(std.testing.io, .{ .kernel_backlog = 64, .mode = .stream, .protocol = .tcp, .reuse_address = true });
    defer listen.deinit(std.testing.io);

    var rmt: RmtHandler = try RmtHandler.init(alloc, std.testing.io, .{ .address = "0.0.0.0", .port = 8099, .key = test_key });

    var rmt_err: ?anyerror = null;

    var file: FileHandler = .init(std.testing.allocator, std.testing.io);
    defer file.deinit();

    try file.source_git_files();
    try file.hash_files();

    var result: ?LsResult = null;

    const thread = try std.Thread.spawn(.{}, runRmtLs, .{ &rmt, &file, &result, &rmt_err });

    var stream = try listen.accept(std.testing.io);
    defer stream.close(std.testing.io);
    try auth.server_handshake(std.testing.io, &test_key, stream);

    var rbuff: [Packet.wire_size]u8 = undefined;

    var reader = stream.reader(std.testing.io, &rbuff);

    const packet = try wire.read_packet(&reader.interface);

    const payload = try wire.read_payload(alloc, packet, &reader.interface);

    var map = try Serializer.bytes_to_string_map(u256, std.testing.allocator, payload.bytes);
    defer map.deinit();

    var reply_changed = std.StringHashMap(u256).init(alloc);
    try reply_changed.put("build.zig", 5);
    var reply_extra = std.StringHashMap(u256).init(alloc);
    try reply_extra.put("gone.txt", 9);

    const reply_files = try LsResult.encode(alloc, &.{"new.txt"}, reply_changed, reply_extra);
    var reply = wire.reply_packet(packet);
    try wire.append_payload_len(&reply, reply_files.bytes.len);
    try wire.write_packet(std.testing.io, reply, stream);
    try wire.write_payload(std.testing.io, reply_files.bytes, stream);

    thread.join();

    if (rmt_err) |e| return e;

    const ls = result.?;
    try std.testing.expect(ls.missing.items.len == 1);
    try std.testing.expectEqualStrings("new.txt", ls.missing.items[0]);
    try std.testing.expect(ls.changed.count() == 1);
    try std.testing.expect(ls.changed.get("build.zig").? == 5);
    try std.testing.expect(ls.extra.count() == 1);
    try std.testing.expect(ls.extra.get("gone.txt").? == 9);

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

    var server: RmtServer = .init(std.testing.allocator, std.testing.io, &file, test_key);
    var server_err: ?anyerror = null;

    const thread = try std.Thread.spawn(.{}, runServerOnce, .{ &server, &listen, &server_err });

    const stream = try addr.connect(std.testing.io, .{ .mode = .stream });
    defer stream.close(std.testing.io);
    try auth.client_handshake(std.testing.io, &test_key, stream);

    try wire.write_packet(std.testing.io, .{ .magic = 0xAF, .token = 42, .command = @intFromEnum(RmtCommands.RMT_UP) }, stream);

    var rbuff: [Packet.wire_size]u8 = undefined;
    var reader = stream.reader(std.testing.io, &rbuff);
    const reply = try wire.read_packet(&reader.interface);

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

    var server: RmtServer = .init(std.testing.allocator, std.testing.io, &file, test_key);
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
    try auth.client_handshake(std.testing.io, &test_key, stream);

    var packet: Packet = .{ .magic = 0xAF, .token = 7, .command = @intFromEnum(RmtCommands.RMT_LS) };
    try wire.append_payload_len(&packet, serialized.bytes.len);
    try wire.write_packet(std.testing.io, packet, stream);
    try wire.write_payload(std.testing.io, serialized.bytes, stream);

    var rbuff: [256]u8 = undefined;
    var reader = stream.reader(std.testing.io, &rbuff);
    const reply = try wire.read_packet(&reader.interface);
    const payload = try wire.read_payload(alloc, reply, &reader.interface);

    thread.join();

    if (server_err) |e| return e;

    try std.testing.expect(reply.magic == 0xAF);
    try std.testing.expect(reply.token == 7);
    try std.testing.expect(reply.command == @intFromEnum(RmtCommands.RMT_LS));

    const ls = try LsResult.decode(payload);

    try std.testing.expect(ls.missing.items.len == 1);
    try std.testing.expectEqualStrings("missing.txt", ls.missing.items[0]);

    // Carries the server's hash so the client can send it back with FR.
    try std.testing.expect(ls.changed.count() == 1);
    try std.testing.expect(ls.changed.get("build.zig").? == file.get_hashes().get("build.zig").?);

    // Everything else the server tracks is unknown to this client.
    try std.testing.expect(ls.extra.count() == file.get_hashes().count() - 2);
    try std.testing.expect(ls.extra.get("src/main.zig").? == file.get_hashes().get("src/main.zig").?);
    try std.testing.expect(ls.extra.get("test.txt") == null);
}

const ClientCall = union(enum) {
    fnp: struct { data: []const u8, name: []const u8, hash: u256 },
    fr: struct { data: []const u8, name: []const u8, remote_hash: u256, local_hash: u256 },
    fd: struct { name: []const u8, remote_hash: u256 },
};

fn runClient(rmt: *RmtHandler, call: ClientCall, err_out: *?anyerror) void {
    const result = switch (call) {
        .fnp => |c| rmt.fnp(c.data, c.name, c.hash),
        .fr => |c| rmt.fr(c.data, c.name, c.remote_hash, c.local_hash),
        .fd => |c| rmt.fd(c.name, c.remote_hash),
    };
    result catch |err| {
        err_out.* = err;
    };
}

const CallErrors = struct { server: ?anyerror = null, client: ?anyerror = null };

/// Runs one client call against one `server.handle`, returning both sides' errors.
fn serveCall(server: *RmtServer, listen: *net.Server, rmt: *RmtHandler, call: ClientCall) !CallErrors {
    var errs: CallErrors = .{};
    const server_thread = try std.Thread.spawn(.{}, runServerOnce, .{ server, listen, &errs.server });
    const client_thread = try std.Thread.spawn(.{}, runClient, .{ rmt, call, &errs.client });
    client_thread.join();
    server_thread.join();
    return errs;
}

fn sha(data: []const u8) u256 {
    var hash: [32]u8 = undefined;
    Sha256.hash(data, &hash, .{});
    return std.mem.readInt(u256, &hash, .little);
}

/// Server rooted in a throwaway git repo, plus a client pointed at it.
const ServerFixture = struct {
    repo: TestRepo,
    listen: net.Server,
    file: FileHandler,
    server: RmtServer,
    rmt: RmtHandler,

    fn init(self: *ServerFixture, repo_path: []const u8, port: u16) !void {
        const io = std.testing.io;
        self.repo = try TestRepo.init(io, repo_path);
        errdefer self.repo.deinit();

        const addr = try net.IpAddress.parse("127.0.0.1", port);
        self.listen = try addr.listen(io, .{ .kernel_backlog = 64, .mode = .stream, .protocol = .tcp, .reuse_address = true });

        self.file = .init_in(std.testing.allocator, io, self.repo.dir);
        self.server = .init(std.testing.allocator, io, &self.file, test_key);
        self.rmt = try RmtHandler.init(std.testing.allocator, io, .{ .address = "127.0.0.1", .port = port, .key = test_key });
    }

    fn deinit(self: *ServerFixture) void {
        self.file.deinit();
        self.listen.deinit(std.testing.io);
        self.repo.deinit();
    }

    fn call(self: *ServerFixture, c: ClientCall) !CallErrors {
        return serveCall(&self.server, &self.listen, &self.rmt, c);
    }

    /// What the server's git index says, after a fresh LS-style source.
    fn tracked(self: *ServerFixture, path: []const u8) !bool {
        try self.file.source_git_files();
        try self.file.hash_files();
        return self.file.get_hashes().contains(path);
    }
};

test "Server FN Command" {
    var fx: ServerFixture = undefined;
    try fx.init(".zig-cache/fn_test", 8102);
    defer fx.deinit();

    const path = "sub/new.txt";
    const data = "fresh file\n";

    // Good transfer: file is created, tracked and staged in git.
    const ok = try fx.call(.{ .fnp = .{ .data = data, .name = path, .hash = sha(data) } });
    if (ok.server) |e| return e;
    if (ok.client) |e| return e;

    var buff: [32]u8 = undefined;
    try std.testing.expectEqualStrings(data, try fx.repo.dir.readFile(std.testing.io, path, &buff));
    try std.testing.expect(try fx.tracked(path));

    // Hash doesn't match the data: server refuses and writes nothing.
    const bad = try fx.call(.{ .fnp = .{ .data = data, .name = "bad.txt", .hash = sha(data) +% 1 } });
    try std.testing.expect(bad.server.? == error.HashMismatch);
    try std.testing.expect(bad.client != null);
    try std.testing.expectError(error.FileNotFound, fx.repo.dir.access(std.testing.io, "bad.txt", .{}));
}

test "Server FR Command" {
    var fx: ServerFixture = undefined;
    try fx.init(".zig-cache/fr_test", 8103);
    defer fx.deinit();

    // Same contents, so only the name can tell them apart.
    _ = try fx.file.create_file("a.txt", "old");
    _ = try fx.file.create_file("b.txt", "old");

    const ok = try fx.call(.{ .fr = .{ .data = "new", .name = "a.txt", .remote_hash = sha("old"), .local_hash = sha("new") } });
    if (ok.server) |e| return e;
    if (ok.client) |e| return e;

    var buff: [16]u8 = undefined;
    try std.testing.expectEqualStrings("new", try fx.repo.dir.readFile(std.testing.io, "a.txt", &buff));
    try std.testing.expectEqualStrings("old", try fx.repo.dir.readFile(std.testing.io, "b.txt", &buff));

    // Client still thinks a.txt is "old", server refuses.
    const stale = try fx.call(.{ .fr = .{ .data = "newer", .name = "a.txt", .remote_hash = sha("old"), .local_hash = sha("newer") } });
    try std.testing.expect(stale.server.? == error.StaleHash);
    try std.testing.expect(stale.client != null);
    try std.testing.expectEqualStrings("new", try fx.repo.dir.readFile(std.testing.io, "a.txt", &buff));
}

test "Server FD Command" {
    var fx: ServerFixture = undefined;
    try fx.init(".zig-cache/fd_test", 8104);
    defer fx.deinit();

    _ = try fx.file.create_file("sub/gone.txt", "bye");
    _ = try fx.file.create_file("keep.txt", "stay");

    // Out of date hash, nothing is deleted.
    const stale = try fx.call(.{ .fd = .{ .name = "sub/gone.txt", .remote_hash = sha("other") } });
    try std.testing.expect(stale.server.? == error.StaleHash);
    try std.testing.expect(stale.client != null);
    try fx.repo.dir.access(std.testing.io, "sub/gone.txt", .{});

    const ok = try fx.call(.{ .fd = .{ .name = "sub/gone.txt", .remote_hash = sha("bye") } });
    if (ok.server) |e| return e;
    if (ok.client) |e| return e;

    try std.testing.expectError(error.FileNotFound, fx.repo.dir.access(std.testing.io, "sub/gone.txt", .{}));
    try std.testing.expect(!try fx.tracked("sub/gone.txt"));
    try std.testing.expect(try fx.tracked("keep.txt"));

    // Paths outside the repo are rejected before anything runs.
    const escape = try fx.call(.{ .fd = .{ .name = "../keep.txt", .remote_hash = 0 } });
    try std.testing.expect(escape.server.? == error.InvalidPath);
}

fn runServerN(server: *RmtServer, listen: *net.Server, n: usize, err_out: *?anyerror) void {
    for (0..n) |_| {
        runServerOnce(server, listen, err_out);
        if (err_out.* != null) return;
    }
}

const RunCapture = struct {
    out: std.Io.Writer.Allocating,
    result: ?handler.RunResult = null,
    err: ?anyerror = null,

    fn init() RunCapture {
        return .{ .out = .init(std.testing.allocator) };
    }

    fn deinit(self: *RunCapture) void {
        if (self.result) |r| switch (r) {
            .failed => |message| std.testing.allocator.free(message),
            else => {},
        };
        self.out.deinit();
    }
};

fn runRmtRun(rmt: *RmtHandler, name: []const u8, capture: *RunCapture) void {
    capture.result = rmt.run(name, &capture.out.writer) catch |err| {
        capture.err = err;
        return;
    };
}

fn serveRun(fx: *ServerFixture, name: []const u8, capture: *RunCapture) !void {
    var server_err: ?anyerror = null;
    const server_thread = try std.Thread.spawn(.{}, runServerOnce, .{ &fx.server, &fx.listen, &server_err });
    const client_thread = try std.Thread.spawn(.{}, runRmtRun, .{ &fx.rmt, name, capture });
    client_thread.join();
    server_thread.join();
    if (server_err) |e| return e;
    if (capture.err) |e| return e;
}

test "Server RUN Command" {
    var fx: ServerFixture = undefined;
    try fx.init(".zig-cache/run_test", 8105);
    defer fx.deinit();

    _ = try fx.file.create_file("rmtbuild.yaml", if (is_windows)
        \\commands:
        \\  hello:
        \\    run: |
        \\      echo out
        \\      echo err 1>&2
        \\      cd
        \\  fail:
        \\    run: exit /b 3
        \\  big:
        \\    run: for /l %%i in (1,1,2000) do @echo xxxxxxxxx
        \\
    else
        \\commands:
        \\  hello:
        \\    run: |
        \\      echo out
        \\      echo err 1>&2
        \\      pwd
        \\  fail:
        \\    run: exit 3
        \\  big:
        \\    run: head -c 20000 /dev/zero | tr '\0' x
        \\  killed:
        \\    run: kill -9 $$
        \\
    );

    // stdout and stderr interleaved in order, run from the repo root.
    {
        var capture = RunCapture.init();
        defer capture.deinit();
        try serveRun(&fx, "hello", &capture);

        try std.testing.expectEqual(handler.RunResult{ .exited = 0 }, capture.result.?);
        const out = capture.out.written();
        if (is_windows) {
            // cmd keeps the space before a redirect.
            try std.testing.expect(std.mem.startsWith(u8, out, "out\r\nerr \r\n"));
            try std.testing.expect(std.mem.endsWith(u8, out, "\\.zig-cache\\run_test\r\n"));
        } else {
            try std.testing.expect(std.mem.startsWith(u8, out, "out\nerr\n"));
            try std.testing.expect(std.mem.endsWith(u8, out, "/.zig-cache/run_test\n"));
        }
    }

    {
        var capture = RunCapture.init();
        defer capture.deinit();
        try serveRun(&fx, "fail", &capture);
        try std.testing.expectEqual(handler.RunResult{ .exited = 3 }, capture.result.?);
    }

    // More than one output packet's worth.
    {
        var capture = RunCapture.init();
        defer capture.deinit();
        try serveRun(&fx, "big", &capture);
        try std.testing.expectEqual(handler.RunResult{ .exited = 0 }, capture.result.?);
        if (is_windows) {
            try std.testing.expectEqual(2000 * "xxxxxxxxx\r\n".len, capture.out.written().len);
        } else {
            try std.testing.expectEqual(20000, capture.out.written().len);
            try std.testing.expect(std.mem.allEqual(u8, capture.out.written(), 'x'));
        }
    }

    // Windows has no signals.
    if (!is_windows) {
        var capture = RunCapture.init();
        defer capture.deinit();
        try serveRun(&fx, "killed", &capture);
        try std.testing.expectEqual(handler.RunResult{ .signal = 9 }, capture.result.?);
    }

    // Only names from the server's config run, never arbitrary strings.
    {
        var capture = RunCapture.init();
        defer capture.deinit();
        try serveRun(&fx, "echo pwned", &capture);
        try std.testing.expect(std.mem.indexOf(u8, capture.result.?.failed, "unknown command 'echo pwned'") != null);
        try std.testing.expect(capture.out.written().len == 0);
    }
}

test "Server RUN without config" {
    var fx: ServerFixture = undefined;
    try fx.init(".zig-cache/run_noconfig_test", 8106);
    defer fx.deinit();

    var capture = RunCapture.init();
    defer capture.deinit();
    try serveRun(&fx, "build", &capture);
    try std.testing.expect(std.mem.indexOf(u8, capture.result.?.failed, "no rmtbuild.yaml") != null);
}

fn runSync(rmt: *RmtHandler, files: *FileHandler, out: *?handler.SyncStats, err_out: *?anyerror) void {
    out.* = rmt.sync(files) catch |err| {
        err_out.* = err;
        return;
    };
}

test "Sync" {
    const io = std.testing.io;
    var fx: ServerFixture = undefined;
    try fx.init(".zig-cache/sync_server_test", 8107);
    defer fx.deinit();

    var client_repo = try TestRepo.init(io, ".zig-cache/sync_client_test");
    defer client_repo.deinit();
    var client: FileHandler = .init_in(std.testing.allocator, io, client_repo.dir);
    defer client.deinit();

    _ = try client.create_file("a.txt", "a");
    _ = try client.create_file("sub/b.txt", "b");
    _ = try client.create_file("same.txt", "same");
    _ = try client.create_file("c.txt", "new c");

    _ = try fx.file.create_file("same.txt", "same");
    _ = try fx.file.create_file("c.txt", "old c");
    _ = try fx.file.create_file("gone.txt", "gone");

    // LS + 2 creates + 1 replace + 1 delete.
    var server_err: ?anyerror = null;
    var client_err: ?anyerror = null;
    var stats: ?handler.SyncStats = null;
    const server_thread = try std.Thread.spawn(.{}, runServerN, .{ &fx.server, &fx.listen, 5, &server_err });
    const client_thread = try std.Thread.spawn(.{}, runSync, .{ &fx.rmt, &client, &stats, &client_err });
    client_thread.join();
    server_thread.join();
    if (server_err) |e| return e;
    if (client_err) |e| return e;

    try std.testing.expectEqual(handler.SyncStats{ .created = 2, .replaced = 1, .deleted = 1 }, stats.?);

    try fx.file.source_git_files();
    try fx.file.hash_files();
    try client.source_git_files();
    try client.hash_files();

    const server_hashes = fx.file.get_hashes();
    try std.testing.expectEqual(client.get_hashes().count(), server_hashes.count());
    var it = client.get_hashes().iterator();
    while (it.next()) |entry| {
        try std.testing.expectEqual(entry.value_ptr.*, server_hashes.get(entry.key_ptr.*).?);
    }
}

test "Server payload cap" {
    var fx: ServerFixture = undefined;
    try fx.init(".zig-cache/cap_test", 8108);
    defer fx.deinit();
    fx.server.max_payload = 64;

    const data = "x" ** 100;
    const big = try fx.call(.{ .fnp = .{ .data = data, .name = "big.txt", .hash = sha(data) } });
    try std.testing.expectEqual(error.PayloadTooLarge, big.server.?);
    try std.testing.expect(big.client != null);
    try std.testing.expectError(error.FileNotFound, fx.repo.dir.access(std.testing.io, "big.txt", .{}));

    // Under the cap still works.
    const small = try fx.call(.{ .fnp = .{ .data = "ok", .name = "small.txt", .hash = sha("ok") } });
    if (small.server) |e| return e;
    if (small.client) |e| return e;
}

test "Wrong key is rejected before any packet" {
    var fx: ServerFixture = undefined;
    try fx.init(".zig-cache/wrong_key_test", 8109);
    defer fx.deinit();
    fx.rmt.info.key[0] ^= 1;

    const result = try fx.call(.{ .fnp = .{ .data = "x", .name = "x.txt", .hash = sha("x") } });
    try std.testing.expectEqual(error.AuthFailed, result.server.?);
    try std.testing.expectEqual(error.AuthRejected, result.client.?);
    try std.testing.expectError(error.FileNotFound, fx.repo.dir.access(std.testing.io, "x.txt", .{}));
}

/// Stand-in for a web server on the server machine: replies "echo:" ++ request once the client
/// stops sending, then closes.
fn echoOnce(listen: *net.Server, err_out: *?anyerror) void {
    const io = std.testing.io;
    const stream = listen.accept(io) catch |err| {
        err_out.* = err;
        return;
    };
    defer stream.close(io);

    var rbuf: [256]u8 = undefined;
    var reader = stream.reader(io, &rbuf);
    var request: [64]u8 = undefined;
    const n = reader.interface.readSliceShort(&request) catch |err| {
        err_out.* = err;
        return;
    };

    var wbuf: [256]u8 = undefined;
    var writer = stream.writer(io, &wbuf);
    writer.interface.print("echo:{s}", .{request[0..n]}) catch |err| {
        err_out.* = err;
        return;
    };
    writer.interface.flush() catch |err| {
        err_out.* = err;
    };
}

test "Server FWD Command" {
    const io = std.testing.io;
    var fx: ServerFixture = undefined;
    try fx.init(".zig-cache/fwd_test", 8120);
    defer fx.deinit();

    // The "web server", listening on the server's localhost.
    const target_addr = try net.IpAddress.parse("127.0.0.1", 8121);
    var target = try target_addr.listen(io, .{ .mode = .stream, .protocol = .tcp, .reuse_address = true });
    defer target.deinit(io);

    var echo_err: ?anyerror = null;
    var server_err: ?anyerror = null;
    const echo_thread = try std.Thread.spawn(.{}, echoOnce, .{ &target, &echo_err });
    const server_thread = try std.Thread.spawn(.{}, runServerOnce, .{ &fx.server, &fx.listen, &server_err });

    const forwarder = try fx.rmt.forward(.{ .local = 8122, .remote = 8121 });
    defer forwarder.stop();

    // A "browser" on the client.
    const local_addr = try net.IpAddress.parse("127.0.0.1", 8122);
    const browser = try local_addr.connect(io, .{ .mode = .stream });
    defer browser.close(io);

    var wbuf: [64]u8 = undefined;
    var writer = browser.writer(io, &wbuf);
    try writer.interface.writeAll("hello");
    try writer.interface.flush();
    try browser.shutdown(io, .send);

    var rbuf: [64]u8 = undefined;
    var reader = browser.reader(io, &rbuf);
    var response: [64]u8 = undefined;
    const n = try reader.interface.readSliceShort(&response);
    try std.testing.expectEqualStrings("echo:hello", response[0..n]);

    echo_thread.join();
    server_thread.join();
    if (echo_err) |e| return e;
    if (server_err) |e| return e;
}

fn runOpenForward(rmt: *RmtHandler, port: u16, err_out: *?anyerror) void {
    const stream = rmt.open_forward(port) catch |err| {
        err_out.* = err;
        return;
    };
    stream.close(rmt.io);
}

test "Server FWD refused" {
    var fx: ServerFixture = undefined;
    try fx.init(".zig-cache/fwd_refused_test", 8123);
    defer fx.deinit();

    var server_err: ?anyerror = null;
    var client_err: ?anyerror = null;
    const server_thread = try std.Thread.spawn(.{}, runServerOnce, .{ &fx.server, &fx.listen, &server_err });
    // Nothing listens on 8124 on the "server".
    const client_thread = try std.Thread.spawn(.{}, runOpenForward, .{ &fx.rmt, 8124, &client_err });
    client_thread.join();
    server_thread.join();

    if (server_err) |e| return e;
    try std.testing.expectEqual(error.ForwardRefused, client_err.?);
}

test "RUN stops the whole command when the client disconnects" {
    const io = std.testing.io;
    var fx: ServerFixture = undefined;
    try fx.init(".zig-cache/run_disconnect_test", 8125);
    defer fx.deinit();

    // The background sleep also holds the output pipe open, so the run only ends this quickly if
    // the whole process group / job is stopped, not just the shell.
    _ = try fx.file.create_file("rmtbuild.yaml", if (is_windows)
        \\commands:
        \\  hang:
        \\    run: |
        \\      echo started
        \\      start /b ping -n 30 127.0.0.1
        \\      ping -n 30 127.0.0.1 >nul
        \\
    else
        \\commands:
        \\  hang:
        \\    run: |
        \\      echo started
        \\      sleep 30 &
        \\      sleep 30
        \\
    );

    var server_err: ?anyerror = null;
    const server_thread = try std.Thread.spawn(.{}, runServerOnce, .{ &fx.server, &fx.listen, &server_err });
    const start = std.Io.Timestamp.now(io, .awake);

    {
        const addr = try net.IpAddress.parse("127.0.0.1", 8125);
        const stream = try addr.connect(io, .{ .mode = .stream });
        defer stream.close(io);
        try auth.client_handshake(io, &test_key, stream);

        var packet: Packet = .{ .magic = 0xAF, .token = 1, .command = @intFromEnum(RmtCommands.RMT_RUN) };
        try wire.append_payload_len(&packet, "hang".len);
        try wire.write_packet(io, packet, stream);
        try wire.write_payload(io, "hang", stream);

        // Wait until it's really running, then walk away.
        var rbuf: [256]u8 = undefined;
        var reader = stream.reader(io, &rbuf);
        const first = try wire.read_packet(&reader.interface);
        const payload = try wire.read_payload(std.testing.allocator, first, &reader.interface);
        defer payload.deinit();
        // The background job may print in the same chunk.
        try std.testing.expect(std.mem.startsWith(u8, payload.bytes, "started"));
    }

    server_thread.join();
    if (server_err) |e| return e;

    const elapsed = start.durationTo(std.Io.Timestamp.now(io, .awake)).toMilliseconds();
    try std.testing.expect(elapsed < 10_000);
}
