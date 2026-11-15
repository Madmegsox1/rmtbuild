//! Remote debugging for a command.
//!
//! .NET Framework only debugs on Windows. The useful remote protocols are:
//!
//! - `rider`: start JetBrains' SSH debug agent (`jetbrains_debugger_agent`) on the
//!   server and tunnel it to the client. Rider's "Attach to Remote Process" speaks
//!   that SSH server and then attaches with its own debugger, which uses ICorDebug
//!   for .NET Framework. This is the path Rider actually supports.
//! - `msvsmon`: start Visual Studio's remote debugger, bound to localhost, and tunnel
//!   it. Visual Studio can attach. Rider cannot.
//! - `mdbg`: run the program under the .NET Framework command-line debugger and bridge
//!   its stdin/stdout over the run connection. No IDE.
//!
//! `netcoredbg` / DAP is not used: stock netcoredbg debugs CoreCLR, not the desktop CLR.
//! Mono's soft debugger debugs Mono, not .NET Framework.
const std = @import("std");
const config = @import("config.zig");
const process = @import("process.zig");

pub const ready_timeout_ms: u64 = 15_000;

/// Set on the remote command when `debug.mode` is `rider` or `msvsmon`.
/// An app can wait on it so Rider has time to attach.
pub const wait_env = "RMTBUILD_DEBUG_WAIT";

pub const rider_agent_env = "RMTBUILD_RIDER_AGENT";
pub const msvsmon_env = "RMTBUILD_MSVSMON";
pub const mdbg_env = "RMTBUILD_MDBG";

pub const Credentials = struct {
    login: []const u8,
    password: []const u8,
    /// Set when the agent printed a port. Caller checks it against the requested one.
    port: ?u16 = null,
};

const PartialCredentials = struct {
    login: ?[]const u8 = null,
    password: ?[]const u8 = null,
    port: ?u16 = null,

    fn complete(self: PartialCredentials) ?Credentials {
        return .{
            .login = self.login orelse return null,
            .password = self.password orelse return null,
            .port = self.port,
        };
    }
};

/// Parses the JetBrains debugger agent's credential banner. Slices point into `text`.
/// Incomplete trailing line is ignored unless `eof` (the agent keeps the pipe open).
pub fn parse_agent_output(text: []const u8, eof: bool) ?Credentials {
    var partial: PartialCredentials = .{};
    scan_agent_output(text, eof, &partial);
    return partial.complete();
}

fn scan_agent_output(text: []const u8, eof: bool, into: *PartialCredentials) void {
    var i: usize = 0;
    while (i < text.len) {
        const end = if (std.mem.indexOfScalarPos(u8, text, i, '\n')) |nl|
            nl
        else blk: {
            if (!eof) break;
            break :blk text.len;
        };
        const line = std.mem.trim(u8, text[i..end], " \t\r");
        i = if (end == text.len) text.len else end + 1;
        if (line.len == 0) continue;

        if (field_value(line, "password")) |value| {
            if (value.len != 0) into.password = value;
        } else if (field_value(line, "username")) |value| {
            if (value.len != 0) into.login = value;
        } else if (field_value(line, "login")) |value| {
            if (value.len != 0) into.login = value;
        } else if (field_value(line, "user")) |value| {
            if (value.len != 0) into.login = value;
        } else if (field_value(line, "port")) |value| {
            into.port = std.fmt.parseInt(u16, value, 10) catch null;
        }
    }
}

fn field_value(line: []const u8, key: []const u8) ?[]const u8 {
    if (line.len < key.len or !std.ascii.startsWithIgnoreCase(line, key)) return null;
    var rest = line[key.len..];
    if (rest.len == 0 or (rest[0] != ':' and rest[0] != '=')) return null;
    rest = rest[1..];
    if (rest.len > 0 and rest[0] == ' ') rest = rest[1..];
    return std.mem.trim(u8, rest, " \t");
}

pub const Notice = struct {
    mode: config.DebugMode,
    started: bool = true,
    port: ?u16 = null,
    login: ?[]const u8 = null,
    password: ?[]const u8 = null,
    /// When false, login and password are omitted. The server console still has them.
    cleartext_password: bool = false,
};

pub fn format_notice(allocator: std.mem.Allocator, notice: Notice) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(allocator);
    errdefer out.deinit();
    try out.writer.print("mode={s}\nstarted={s}\n", .{ @tagName(notice.mode), if (notice.started) "1" else "0" });
    if (notice.port) |port| try out.writer.print("port={d}\n", .{port});
    if (notice.mode == .rider) {
        try out.writer.print("cleartext_password={s}\n", .{if (notice.cleartext_password) "1" else "0"});
        if (notice.cleartext_password) {
            if (notice.login) |login| try out.writer.print("login={s}\n", .{login});
            if (notice.password) |password| try out.writer.print("password={s}\n", .{password});
        }
    }
    return out.toOwnedSlice();
}

pub fn notice_value(text: []const u8, key: []const u8) ?[]const u8 {
    var i: usize = 0;
    while (i < text.len) {
        const end = std.mem.indexOfScalarPos(u8, text, i, '\n') orelse text.len;
        const line = text[i..end];
        i = if (end == text.len) text.len else end + 1;
        if (std.mem.startsWith(u8, line, key) and line.len > key.len and line[key.len] == '=') {
            return std.mem.trim(u8, line[key.len + 1 ..], " \t\r");
        }
    }
    return null;
}

/// Text the client prints when a debug notice arrives. `local` is the forwarded client port.
pub fn format_banner(w: *std.Io.Writer, notice_text: []const u8, local: ?u16) !void {
    const mode = notice_value(notice_text, "mode") orelse "debug";
    const started = if (notice_value(notice_text, "started")) |s| !std.mem.eql(u8, s, "0") else true;
    const port = if (notice_value(notice_text, "port")) |p| std.fmt.parseInt(u16, p, 10) catch null else null;
    const shown = local orelse port orelse 0;

    if (std.mem.eql(u8, mode, "mdbg")) {
        try w.writeAll(
            \\rmtbuild: MDbg is running on the server. Commands go to it (help, break, go, next, out, print, quit).
            \\
        );
        return;
    }

    if (std.mem.eql(u8, mode, "msvsmon")) {
        try w.print(
            \\rmtbuild: WARNING: msvsmon is running with /noauth, bound to the server's localhost.
            \\rmtbuild: Any local user on that machine can attach and run code as the user running rmtbuild.
            \\rmtbuild: The forwarded port exposes that to whoever can open it on this machine.
            \\rmtbuild: Visual Studio remote debugger is forwarded to 127.0.0.1:{d}
            \\rmtbuild: Visual Studio: Debug > Attach to Process, connection type "Remote (no authentication)", target 127.0.0.1:{d}
            \\rmtbuild: Do not open this port on the server firewall. Loopback is the only listener, on purpose.
            \\
        , .{ shown, shown });
        return;
    }

    // rider
    if (!started) {
        try w.print(
            \\rmtbuild: forwarding the server's SSH port to 127.0.0.1:{d}
            \\rmtbuild: Rider: Run | Attach to Remote Process
            \\rmtbuild:   host: 127.0.0.1
            \\rmtbuild:   port: {d}
            \\rmtbuild:   use the SSH account that can log into the server
            \\
        , .{ shown, shown });
        return;
    }

    const clear = if (notice_value(notice_text, "cleartext_password")) |v| std.mem.eql(u8, v, "1") else false;
    if (!clear) {
        try w.print(
            \\rmtbuild: WARNING: the JetBrains agent password was NOT sent to this machine.
            \\rmtbuild: The rmtbuild connection is not encrypted, and the agent listens on every interface.
            \\rmtbuild: Anyone who can sniff this network and learn the password can attach a debugger.
            \\rmtbuild: The password is on the server console. Firewall the agent port off the LAN.
            \\rmtbuild: Set debug.allow_cleartext_password: true only if you accept sending it in cleartext.
            \\rmtbuild: Rider: Run | Attach to Remote Process, host 127.0.0.1, port {d}
            \\
        , .{shown});
        return;
    }

    const login = notice_value(notice_text, "login") orelse "";
    const password = notice_value(notice_text, "password") orelse "";
    try w.print(
        \\rmtbuild: WARNING: agent password is on this unencrypted connection, in cleartext.
        \\rmtbuild: The agent listens on every interface. Firewall that port. Anyone who can read
        \\rmtbuild: this network can attach a debugger with the password below.
        \\rmtbuild: JetBrains debugger agent is forwarded to 127.0.0.1:{d}
        \\rmtbuild: Rider: Run | Attach to Remote Process
        \\rmtbuild:   host: 127.0.0.1
        \\rmtbuild:   port: {d}
        \\rmtbuild:   user: {s}
        \\rmtbuild:   password: {s}
        \\rmtbuild: Attach to the .NET Framework process from this command. A Debug build with a PDB next to the exe is required.
        \\
    , .{ shown, shown, login, password });
}

pub fn print_notice(notice_text: []const u8, local: ?u16) void {
    var buf: [2048]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    format_banner(&w, notice_text, local) catch {
        std.debug.print("{s}\n", .{notice_text});
        return;
    };
    std.debug.print("{s}", .{w.buffered()});
}

pub fn default_agent_name(os: std.Target.Os.Tag, mode: config.DebugMode) []const u8 {
    return switch (mode) {
        .rider => if (os == .windows) "jetbrains_debugger_agent.exe" else "jetbrains_debugger_agent",
        .msvsmon => "msvsmon.exe",
        .mdbg => "MDbg.exe",
    };
}

pub fn env_name(mode: config.DebugMode) []const u8 {
    return switch (mode) {
        .rider => rider_agent_env,
        .msvsmon => msvsmon_env,
        .mdbg => mdbg_env,
    };
}

/// `configured` (from rmtbuild.yaml) wins, then the mode's env var, then the default file name.
pub fn resolve_agent(os: std.Target.Os.Tag, mode: config.DebugMode, configured: ?[]const u8, from_env: ?[]const u8) []const u8 {
    if (configured) |path| if (path.len != 0) return path;
    if (from_env) |path| if (path.len != 0) return path;
    return default_agent_name(os, mode);
}

fn is_batch(path: []const u8) bool {
    return std.ascii.endsWithIgnoreCase(path, ".cmd") or std.ascii.endsWithIgnoreCase(path, ".bat");
}

/// Argv for the JetBrains agent or msvsmon. Every slice is allocated in `arena`.
pub fn listener_argv(
    arena: std.mem.Allocator,
    os: std.Target.Os.Tag,
    mode: config.DebugMode,
    agent: []const u8,
    port: u16,
) ![]const []const u8 {
    const port_arg = switch (mode) {
        .rider => try std.fmt.allocPrint(arena, "-port={d}", .{port}),
        .msvsmon => try std.fmt.allocPrint(arena, "/port:{d}", .{port}),
        .mdbg => unreachable,
    };

    if (mode == .rider) {
        if (os == .windows and is_batch(agent)) {
            const argv = try arena.alloc([]const u8, 5);
            argv[0] = "cmd.exe";
            argv[1] = "/d";
            argv[2] = "/c";
            argv[3] = agent;
            argv[4] = port_arg;
            return argv;
        }
        const argv = try arena.alloc([]const u8, 2);
        argv[0] = agent;
        argv[1] = port_arg;
        return argv;
    }

    // /hostname 127.0.0.1 keeps /noauth off the network. rmtbuild reaches it through localhost.
    const flags = [_][]const u8{ agent, "/noauth", "/anyuser", "/nosecuritywarn", "/silent", "/hostname", "127.0.0.1", port_arg };
    if (os == .windows and is_batch(agent)) {
        const wrapped = try arena.alloc([]const u8, 3 + flags.len);
        wrapped[0] = "cmd.exe";
        wrapped[1] = "/d";
        wrapped[2] = "/c";
        @memcpy(wrapped[3..], &flags);
        return wrapped;
    }
    return try arena.dupe([]const u8, &flags);
}

/// Argv for MDbg: `MDbg.exe <program> <args...>`.
pub fn mdbg_argv(
    arena: std.mem.Allocator,
    os: std.Target.Os.Tag,
    agent: []const u8,
    program: []const u8,
    args: []const []const u8,
) ![]const []const u8 {
    const body_len = 2 + args.len;
    const prefix: usize = if (os == .windows and is_batch(agent)) 3 else 0;
    const argv = try arena.alloc([]const u8, prefix + body_len);
    if (prefix != 0) {
        argv[0] = "cmd.exe";
        argv[1] = "/d";
        argv[2] = "/c";
    }
    argv[prefix] = agent;
    argv[prefix + 1] = program;
    @memcpy(argv[prefix + 2 ..], args);
    return argv;
}

/// Prepends the wait environment variable so a .NET Framework app can spin until a debugger attaches.
pub fn with_wait_env(allocator: std.mem.Allocator, os: std.Target.Os.Tag, script: []const u8) ![]u8 {
    const prefix = if (os == .windows) "set " ++ wait_env ++ "=1\n" else "export " ++ wait_env ++ "=1\n";
    return std.fmt.allocPrint(allocator, "{s}{s}", .{ prefix, script });
}

pub fn connect_localhost(io: std.Io, port: u16) !std.Io.net.Stream {
    const v4 = try std.Io.net.IpAddress.parse("127.0.0.1", port);
    return v4.connect(io, .{ .mode = .stream }) catch {
        const v6 = try std.Io.net.IpAddress.parse("::1", port);
        return v6.connect(io, .{ .mode = .stream });
    };
}

pub fn port_open(io: std.Io, port: u16) bool {
    if (connect_localhost(io, port)) |stream| {
        stream.close(io);
        return true;
    } else |_| return false;
}

/// Returns once something accepts TCP on localhost:`port`, or `error.DebugPortClosed`.
pub fn wait_listening(io: std.Io, port: u16, timeout_ms: u64) error{DebugPortClosed}!void {
    const start = std.Io.Timestamp.now(io, .awake);
    while (true) {
        if (connect_localhost(io, port)) |stream| {
            stream.close(io);
            return;
        } else |_| {}

        const elapsed = start.durationTo(std.Io.Timestamp.now(io, .awake)).toMilliseconds();
        if (elapsed > timeout_ms) return error.DebugPortClosed;
        io.sleep(.fromMilliseconds(50), .awake) catch return error.DebugPortClosed;
    }
}

const capture_cap = 32 * 1024;

/// A debugger helper process (the JetBrains agent or msvsmon) whose stdout is captured
/// until `deinit`, which kills the whole process tree.
pub const Listener = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    running: process.Running,
    stdout_thread: std.Thread,
    stderr_thread: std.Thread,
    lock: std.Io.Mutex = .init,
    stdout_buf: []u8,
    stderr_buf: []u8,
    stdout_len: usize = 0,
    stderr_len: usize = 0,
    stdout_eof: std.atomic.Value(bool) = .init(false),
    stderr_eof: std.atomic.Value(bool) = .init(false),
    login: ?[]u8 = null,
    password: ?[]u8 = null,

    /// Heap allocated so the capture threads can hold pointers into it.
    pub fn spawn(
        allocator: std.mem.Allocator,
        io: std.Io,
        cwd: std.process.Child.Cwd,
        argv: []const []const u8,
    ) !*Listener {
        const stdout_buf = try allocator.alloc(u8, capture_cap);
        const stderr_buf = allocator.alloc(u8, capture_cap) catch |err| {
            allocator.free(stdout_buf);
            return err;
        };
        const self = allocator.create(Listener) catch |err| {
            allocator.free(stdout_buf);
            allocator.free(stderr_buf);
            return err;
        };
        self.* = .{
            .allocator = allocator,
            .io = io,
            .running = undefined,
            .stdout_thread = undefined,
            .stderr_thread = undefined,
            .stdout_buf = stdout_buf,
            .stderr_buf = stderr_buf,
        };
        // Stored once. `Running` owns the process and must not be copied.
        self.running = process.spawn_argv(io, allocator, cwd, argv, .{ .stderr = .pipe }) catch |err| {
            allocator.free(stdout_buf);
            allocator.free(stderr_buf);
            allocator.destroy(self);
            return err;
        };

        self.stdout_thread = std.Thread.spawn(.{}, pump, .{ io, self.running.output(), self.stdout_buf, &self.stdout_len, &self.stdout_eof, &self.lock }) catch |err| {
            self.running.deinit();
            allocator.free(stdout_buf);
            allocator.free(stderr_buf);
            allocator.destroy(self);
            return err;
        };
        self.stderr_thread = std.Thread.spawn(.{}, pump, .{ io, self.running.error_output().?, self.stderr_buf, &self.stderr_len, &self.stderr_eof, &self.lock }) catch |err| {
            self.running.kill();
            self.stdout_thread.join();
            self.running.deinit();
            allocator.free(self.stdout_buf);
            allocator.free(self.stderr_buf);
            allocator.destroy(self);
            return err;
        };
        return self;
    }

    pub fn deinit(self: *Listener) void {
        const allocator = self.allocator;
        self.running.kill();
        self.stdout_thread.join();
        self.stderr_thread.join();
        self.running.deinit();
        if (self.login) |s| allocator.free(s);
        if (self.password) |s| allocator.free(s);
        allocator.free(self.stdout_buf);
        allocator.free(self.stderr_buf);
        allocator.destroy(self);
    }

    /// Blocks until the agent prints login and password, or gives up.
    /// The returned slices are owned by this listener (freed by `deinit`).
    pub fn wait_credentials(self: *Listener, expected_port: u16) !Credentials {
        const start = std.Io.Timestamp.now(self.io, .awake);
        while (true) {
            if (try self.poll_credentials(expected_port)) |creds| return creds;
            if (self.stdout_eof.load(.acquire) and self.stderr_eof.load(.acquire)) return error.AgentExited;

            const elapsed = start.durationTo(std.Io.Timestamp.now(self.io, .awake)).toMilliseconds();
            if (elapsed > ready_timeout_ms) return error.AgentTimeout;
            self.io.sleep(.fromMilliseconds(20), .awake) catch return error.AgentTimeout;
        }
    }

    fn poll_credentials(self: *Listener, expected_port: u16) !?Credentials {
        self.lock.lockUncancelable(self.io);
        defer self.lock.unlock(self.io);

        // The agent may write the banner to stdout or stderr.
        var partial: PartialCredentials = .{};
        // stdout wins when both streams carry a field.
        scan_agent_output(self.stderr_buf[0..self.stderr_len], self.stderr_eof.load(.acquire), &partial);
        scan_agent_output(self.stdout_buf[0..self.stdout_len], self.stdout_eof.load(.acquire), &partial);
        const parsed = partial.complete() orelse return null;
        if (parsed.port) |got| if (got != expected_port) return error.PortMismatch;

        if (self.login == null) self.login = try self.allocator.dupe(u8, parsed.login);
        if (self.password == null) self.password = try self.allocator.dupe(u8, parsed.password);
        return .{
            .login = self.login.?,
            .password = self.password.?,
            .port = parsed.port,
        };
    }

    /// Both pipes closed: the helper has gone away (or at least isn't writing anymore).
    pub fn stdio_ended(self: *const Listener) bool {
        return self.stdout_eof.load(.acquire) and self.stderr_eof.load(.acquire);
    }

    pub fn copy_output(self: *Listener, allocator: std.mem.Allocator) ![]u8 {
        self.lock.lockUncancelable(self.io);
        defer self.lock.unlock(self.io);
        var out: std.Io.Writer.Allocating = .init(allocator);
        errdefer out.deinit();
        if (self.stdout_len != 0) {
            try out.writer.writeAll(self.stdout_buf[0..self.stdout_len]);
            try out.writer.writeAll("\n");
        }
        if (self.stderr_len != 0) try out.writer.writeAll(self.stderr_buf[0..self.stderr_len]);
        return out.toOwnedSlice();
    }
};

fn pump(
    io: std.Io,
    file: std.Io.File,
    buf: []u8,
    len: *usize,
    eof: *std.atomic.Value(bool),
    lock: *std.Io.Mutex,
) void {
    var tmp: [1024]u8 = undefined;
    while (true) {
        const n = file.readStreaming(io, &.{&tmp}) catch break;
        if (n == 0) break;
        lock.lockUncancelable(io);
        const room = buf.len - len.*;
        const take = @min(room, n);
        if (take != 0) {
            @memcpy(buf[len.*..][0..take], tmp[0..take]);
            len.* += take;
        }
        lock.unlock(io);
        // Past the cap, keep reading so a chatty helper doesn't block on a full pipe.
        // Stopping here used to look like the process had exited.
    }
    eof.store(true, .release);
}

// ---------------------------------------------------------------- tests

test "parse JetBrains agent banner" {
    const text =
        \\Please, use these credentials to establish SSH connection
        \\Login: rideruser
        \\Password: s3cret
        \\Port: 7777
        \\
    ;
    const creds = parse_agent_output(text, true).?;
    try std.testing.expectEqualStrings("rideruser", creds.login);
    try std.testing.expectEqualStrings("s3cret", creds.password);
    try std.testing.expectEqual(@as(?u16, 7777), creds.port);

    // A partial last line is not a credential yet.
    try std.testing.expect(parse_agent_output("Login: rideruser\nPassword: sec", false) == null);
    const done = parse_agent_output("login: A\npassword: B\n", false).?;
    try std.testing.expectEqualStrings("A", done.login);
    try std.testing.expect(done.port == null);
}

test "listener and mdbg argv" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const rider = try listener_argv(a, .linux, .rider, "jetbrains_debugger_agent", 7777);
    try expect_argv(&.{ "jetbrains_debugger_agent", "-port=7777" }, rider);

    const batch = try listener_argv(a, .windows, .rider, "tools\\agent.cmd", 7777);
    try expect_argv(&.{ "cmd.exe", "/d", "/c", "tools\\agent.cmd", "-port=7777" }, batch);

    const vs = try listener_argv(a, .windows, .msvsmon, "msvsmon.exe", 4026);
    try expect_argv(&.{
        "msvsmon.exe", "/noauth", "/anyuser", "/nosecuritywarn", "/silent", "/hostname", "127.0.0.1", "/port:4026",
    }, vs);

    const mdbg = try mdbg_argv(a, .windows, "MDbg.exe", "bin\\Debug\\App.exe", &.{ "--x" });
    try expect_argv(&.{ "MDbg.exe", "bin\\Debug\\App.exe", "--x" }, mdbg);

    try std.testing.expectEqualStrings("jetbrains_debugger_agent.exe", resolve_agent(.windows, .rider, null, null));
    try std.testing.expectEqualStrings("C:\\agent.exe", resolve_agent(.windows, .rider, "C:\\agent.exe", "ignored"));
    try std.testing.expectEqualStrings("from-env", resolve_agent(.linux, .mdbg, null, "from-env"));
}

fn expect_argv(expected: []const []const u8, actual: []const []const u8) !void {
    try std.testing.expectEqual(expected.len, actual.len);
    for (expected, actual) |want, got| try std.testing.expectEqualStrings(want, got);
}

test "notice banner" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const notice = try format_notice(arena.allocator(), .{
        .mode = .rider,
        .port = 7777,
        .login = "rideruser",
        .password = "s3cret",
        .cleartext_password = true,
    });
    var buf: [2048]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try format_banner(&w, notice, 7000);
    const text = w.buffered();
    try std.testing.expect(std.mem.indexOf(u8, text, "127.0.0.1:7000") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "rideruser") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "s3cret") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "Attach to Remote Process") != null);
}

test "notice omits the password unless cleartext is opted in" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const hidden = try format_notice(arena.allocator(), .{
        .mode = .rider,
        .port = 7777,
        .login = "rideruser",
        .password = "s3cret",
    });
    try std.testing.expect(std.mem.indexOf(u8, hidden, "s3cret") == null);
    try std.testing.expect(std.mem.indexOf(u8, hidden, "cleartext_password=0\n") != null);

    var buf: [2048]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try format_banner(&w, hidden, 7777);
    try std.testing.expect(std.mem.indexOf(u8, w.buffered(), "NOT sent") != null);
    try std.testing.expect(std.mem.indexOf(u8, w.buffered(), "s3cret") == null);
}

test "capture keeps draining after the buffer fills" {
    const io = std.testing.io;
    const builtin = @import("builtin");
    const argv: []const []const u8 = if (builtin.os.tag == .windows)
        &.{ "powershell.exe", "-NoProfile", "-Command", "'x' * 40000 | Write-Host -NoNewline; Start-Sleep -Seconds 30" }
    else
        &.{ "sh", "-c", "python3 -c 'import sys,time; sys.stdout.write(\"x\"*40000); sys.stdout.flush(); time.sleep(30)'" };

    const listener = try Listener.spawn(std.testing.allocator, io, .inherit, argv);
    defer listener.deinit();

    const start = std.Io.Timestamp.now(io, .awake);
    while (listener.stdout_len < listener.stdout_buf.len) {
        const elapsed = start.durationTo(std.Io.Timestamp.now(io, .awake)).toMilliseconds();
        if (elapsed > 5_000) return error.TestExpectedEqual;
        io.sleep(.fromMilliseconds(20), .awake) catch {};
    }
    io.sleep(.fromMilliseconds(200), .awake) catch {};
    try std.testing.expect(!listener.stdout_eof.load(.acquire));
    try std.testing.expect(!listener.stdio_ended());
}

test "wait until a port listens" {
    const io = std.testing.io;
    const port: u16 = 18321;
    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", port);
    var listener = try addr.listen(io, .{ .mode = .stream, .protocol = .tcp, .reuse_address = true });
    defer listener.deinit(io);

    const thread = try std.Thread.spawn(.{}, accept_one, .{ &listener });
    try wait_listening(io, port, 2_000);
    thread.join();

    try std.testing.expectError(error.DebugPortClosed, wait_listening(io, 18322, 200));
}

fn accept_one(listener: *std.Io.net.Server) void {
    const stream = listener.accept(std.testing.io) catch return;
    stream.close(std.testing.io);
}

test "wait env prefix" {
    const posix = try with_wait_env(std.testing.allocator, .linux, "echo hi");
    defer std.testing.allocator.free(posix);
    try std.testing.expectEqualStrings("export " ++ wait_env ++ "=1\necho hi", posix);

    const win = try with_wait_env(std.testing.allocator, .windows, "echo hi");
    defer std.testing.allocator.free(win);
    try std.testing.expectEqualStrings("set " ++ wait_env ++ "=1\necho hi", win);
}
