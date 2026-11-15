const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const config = @import("config.zig");
const FileHandler = @import("file.zig").FileHandler;
const handler = @import("rmt/handler.zig");
const auth = @import("rmt/auth.zig");
const debug_session = @import("debug_session.zig");

const usage =
    \\usage: rmtbuild <command>                         sync files to the server, then run <command> there
    \\       rmtbuild serve [--listen ADDR] [--port N]  serve the git repo in the current directory
    \\       rmtbuild keygen [--force]                  create the shared key both sides need
    \\
;

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(arena);

    // Before loading the config, keygen doesn't need one.
    if (args.len >= 2 and std.mem.eql(u8, args[1], "keygen")) return keygen(init, args[2..]);

    var diag: config.Diagnostic = .{};
    const cfg: ?config.Config = config.Config.load(arena, io, .cwd(), &diag) catch |err| switch (err) {
        error.FileNotFound => null,
        error.InvalidConfig => fatal("{s}: {f}", .{ config.file_name, diag }),
        else => fatal("can't read {s}: {s}", .{ config.file_name, @errorName(err) }),
    };

    if (args.len < 2 or std.mem.eql(u8, args[1], "help") or std.mem.eql(u8, args[1], "--help")) {
        print_usage(cfg);
        return;
    }

    if (std.mem.eql(u8, args[1], "serve")) {
        return serve(init, cfg orelse .{}, args[2..]);
    }

    if (args.len > 2) fatal("unexpected argument '{s}'\n\n" ++ usage, .{args[2]});
    const c = cfg orelse fatal("no {s} in the current directory", .{config.file_name});
    std.process.exit(try run_command(init, c, args[1]));
}

fn keygen(init: std.process.Init, args: []const [:0]const u8) !void {
    var force = false;
    for (args) |arg| {
        if (std.mem.eql(u8, arg, "--force")) force = true else fatal("unknown option '{s}'\n\n" ++ usage, .{arg});
    }

    const path = auth.default_key_path(init.arena.allocator(), init.environ_map) catch
        fatal("can't find a config directory, set " ++ (if (builtin.os.tag == .windows) "APPDATA" else "HOME") ++ " or XDG_CONFIG_HOME", .{});
    const key = try auth.generate_key(init.io);
    auth.write_key_file(init.io, path, key, force) catch |err| switch (err) {
        error.PathAlreadyExists => fatal("{s} already exists, use --force to replace it (both sides then need the new key)", .{path}),
        else => fatal("can't write {s}: {s}", .{ path, @errorName(err) }),
    };

    std.debug.print(
        \\rmtbuild: wrote a new key to {s}
        \\copy it to the same path on the other machine (or set {s} there), e.g.
        \\  scp {s} buildbox:.config/rmtbuild/key
        \\
    , .{ path, auth.key_env, path });
}

fn load_key(init: std.process.Init) auth.Key {
    const path = auth.default_key_path(init.arena.allocator(), init.environ_map) catch
        fatal("can't find a config directory, set " ++ (if (builtin.os.tag == .windows) "APPDATA" else "HOME") ++ " or XDG_CONFIG_HOME", .{});
    return auth.load_key(init.io, init.environ_map, path) catch |err| switch (err) {
        error.FileNotFound => fatal("no key at {s}, run `rmtbuild keygen` and copy it to the other machine", .{path}),
        error.KeyFileTooOpen => fatal("{s} is readable by other users, run `chmod 600 {s}`", .{ path, path }),
        error.InvalidKey => fatal("{s} doesn't hold a valid key, regenerate it with `rmtbuild keygen --force`", .{path}),
        error.InvalidKeyEnv => fatal("{s} isn't a valid key (64 hex characters)", .{auth.key_env}),
        else => fatal("can't read {s}: {s}", .{ path, @errorName(err) }),
    };
}

fn serve(init: std.process.Init, defaults: config.Config, args: []const [:0]const u8) !void {
    const io = init.io;
    var listen = defaults.listen;
    var port = defaults.port;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const flag = args[i];
        if (i + 1 == args.len) fatal("{s} needs a value\n\n" ++ usage, .{flag});
        i += 1;
        if (std.mem.eql(u8, flag, "--listen")) {
            listen = args[i];
        } else if (std.mem.eql(u8, flag, "--port")) {
            port = std.fmt.parseInt(u16, args[i], 10) catch fatal("'{s}' isn't a port number", .{args[i]});
        } else {
            fatal("unknown option '{s}'\n\n" ++ usage, .{flag});
        }
    }

    var files = FileHandler.init(init.gpa, io);
    defer files.deinit();
    // Fail now rather than on the first client if this isn't a git repo.
    files.source_git_files() catch fatal("the current directory must be a git repo", .{});

    const addr = std.Io.net.IpAddress.parse(listen, port) catch fatal("'{s}' isn't an IP address", .{listen});
    var listener = addr.listen(io, .{ .mode = .stream, .protocol = .tcp, .reuse_address = true }) catch |err|
        fatal("can't listen on {s}:{d}: {s}", .{ listen, port, @errorName(err) });
    defer listener.deinit(io);

    var server = handler.RmtServer.init(init.gpa, io, &files, load_key(init));
    server.max_payload = defaults.max_payload_mb * 1024 * 1024;
    server.rider_agent = try dupe_env(init.arena.allocator(), init.environ_map, debug_session.rider_agent_env);
    server.msvsmon_agent = try dupe_env(init.arena.allocator(), init.environ_map, debug_session.msvsmon_env);
    server.mdbg_agent = try dupe_env(init.arena.allocator(), init.environ_map, debug_session.mdbg_env);

    handler.stop_commands_on_exit();
    std.log.info("serving on {s}:{d}", .{ listen, port });
    try server.serve(&listener);
}

/// Returns the process exit code: the remote command's, 128 + signal, or 1 if it couldn't run.
fn run_command(init: std.process.Init, cfg: config.Config, name: []const u8) !u8 {
    const io = init.io;

    if (!cfg.commands.contains(name)) {
        std.debug.print("rmtbuild: unknown command '{s}'\n\n", .{name});
        print_usage(cfg);
        return 1;
    }

    var files = FileHandler.init(init.gpa, io);
    defer files.deinit();
    files.source_git_files() catch fatal("the current directory must be a git repo", .{});
    try files.hash_files();

    var rmt = handler.RmtHandler.init(init.gpa, io, .{ .address = cfg.address, .port = cfg.port, .key = load_key(init) }) catch
        fatal("server.address '{s}' isn't an IP address", .{cfg.address});

    // Before syncing, so a local port that's already taken fails straight away.
    const command = cfg.commands.get(name).?;
    for (command.forward) |fwd| try forward_or_die(&rmt, fwd, .command);
    var debug_local: ?u16 = null;
    if (command.debug) |dbg| if (dbg.client_forward()) |fwd| {
        try forward_or_die(&rmt, fwd, .debug);
        debug_local = fwd.local;
    };

    const stats = rmt.sync(&files) catch |err| switch (err) {
        error.AuthRejected => fatal("{s}:{d} rejected our key, both sides need the same key", .{ cfg.address, cfg.port }),
        error.ServerAuthFailed => fatal("{s}:{d} doesn't have our key, it may not be your server", .{ cfg.address, cfg.port }),
        else => fatal("sync with {s}:{d} failed: {s}", .{ cfg.address, cfg.port, @errorName(err) }),
    };
    std.debug.print("rmtbuild: synced {d} new, {d} changed, {d} deleted\n", .{ stats.created, stats.replaced, stats.deleted });
    for (command.forward) |fwd| {
        std.debug.print("rmtbuild: forwarding http://localhost:{d} -> server port {d}\n", .{ fwd.local, fwd.remote });
    }
    if (debug_local) |local| if (command.debug) |dbg| if (dbg.port) |remote| {
        std.debug.print("rmtbuild: forwarding debugger localhost:{d} -> server port {d}\n", .{ local, remote });
    };

    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer: Io.File.Writer = .init(.stdout(), io, &stdout_buffer);

    const result = rmt.run(name, &stdout_writer.interface, .{
        .debug_local = debug_local,
        .stdin = if (command.debug) |dbg| if (dbg.mode == .mdbg) std.Io.File.stdin() else null else null,
    }) catch |err| switch (err) {
        error.EndOfStream => fatal("lost the connection to the server while '{s}' was running", .{name}),
        else => fatal("running '{s}' failed: {s}", .{ name, @errorName(err) }),
    };

    return switch (result) {
        .exited => |code| @truncate(code),
        .signal => |sig| blk: {
            std.debug.print("rmtbuild: '{s}' was killed by signal {d}\n", .{ name, sig });
            break :blk 128 +| @as(u8, @truncate(sig));
        },
        .failed => |message| blk: {
            std.debug.print("rmtbuild: {s}\n", .{message});
            break :blk 1;
        },
    };
}

fn print_usage(cfg: ?config.Config) void {
    std.debug.print("{s}", .{usage});
    const c = cfg orelse {
        std.debug.print("\nno {s} in the current directory\n", .{config.file_name});
        return;
    };
    std.debug.print("\ncommands ({s}):\n", .{config.file_name});
    if (c.commands.count() == 0) std.debug.print("  (none)\n", .{});
    var it = c.commands.iterator();
    while (it.next()) |entry| {
        // First line of the script is enough to recognise it.
        const first = std.mem.sliceTo(entry.value_ptr.run, '\n');
        if (entry.value_ptr.debug) |dbg| {
            std.debug.print("  {s: <12} {s}  [debug:{s}]\n", .{ entry.key_ptr.*, first, @tagName(dbg.mode) });
        } else {
            std.debug.print("  {s: <12} {s}\n", .{ entry.key_ptr.*, first });
        }
    }
}

fn dupe_env(allocator: std.mem.Allocator, environ: *const std.process.Environ.Map, key: []const u8) !?[]const u8 {
    const value = environ.get(key) orelse return null;
    if (value.len == 0) return null;
    return try allocator.dupe(u8, value);
}

const ForwardKind = enum { command, debug };

fn forward_or_die(rmt: *handler.RmtHandler, fwd: config.Forward, kind: ForwardKind) !void {
    _ = rmt.forward(fwd) catch |err| switch (err) {
        error.AddressInUse => switch (kind) {
            .command => fatal("localhost:{d} is already in use, forward another port with e.g. 'forward: {d}:{d}'", .{ fwd.local, fwd.local +| 1, fwd.remote }),
            .debug => fatal("localhost:{d} is already in use for the debugger. Set debug.local to a free port (it is forwarded to the server's {d}).", .{ fwd.local, fwd.remote }),
        },
        else => fatal("can't forward localhost:{d}: {s}", .{ fwd.local, @errorName(err) }),
    };
}

fn fatal(comptime fmt: []const u8, args: anytype) noreturn {
    std.debug.print("rmtbuild: " ++ fmt ++ "\n", args);
    std.process.exit(1);
}

test {
    _ = @import("config.zig");
    _ = @import("debug_session.zig");
    _ = @import("file.zig");
    _ = @import("process.zig");
    _ = @import("rmt/pack.zig");
    _ = @import("rmt/handler.zig");
    _ = @import("rmt/handler_test.zig");
    _ = @import("rmt/auth.zig");
    _ = @import("rmt/serializer.zig");
    _ = @import("rmt/wire.zig");
}
