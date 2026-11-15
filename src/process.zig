//! Runs a configured command so that it, and everything it starts, can be stopped together.
//! stdout and stderr come out of one pipe, interleaved in the order they were written.
//!
//! - POSIX: `sh -c`, in its own process group.
//! - Windows: the script runs as a `.cmd` batch file, inside a Job Object that kills every process
//!   in it when closed, so commands can't outlive the server even if it's killed outright.
const std = @import("std");
const builtin = @import("builtin");

const is_windows = builtin.os.tag == .windows;

pub const Exit = union(enum) {
    exited: u32,
    signal: u32,
    unknown: u32,
};

pub const Running = struct {
    io: std.Io,
    child: std.process.Child,
    tree: Tree,
    waited: bool = false,

    pub fn output(self: *Running) std.Io.File {
        return self.child.stdout.?;
    }

    /// The write end of the child's stdin, when spawned with `stdin = .pipe`.
    pub fn input(self: *Running) ?std.Io.File {
        return self.child.stdin;
    }

    /// Closes the child's stdin so it sees EOF. Safe to call twice.
    pub fn close_input(self: *Running) void {
        if (self.child.stdin) |file| {
            file.close(self.io);
            self.child.stdin = null;
        }
    }

    /// The read end of the child's stderr, when spawned with `stderr = .pipe`.
    pub fn error_output(self: *Running) ?std.Io.File {
        return self.child.stderr;
    }

    /// Asks the whole tree to stop (SIGTERM). Windows has no polite equivalent, so it's killed.
    /// Safe to call from another thread.
    pub fn stop(self: *const Running) void {
        self.tree.signal(.stop);
    }

    /// Safe to call from another thread.
    pub fn kill(self: *const Running) void {
        self.tree.signal(.kill);
    }

    pub fn wait(self: *Running) !Exit {
        const term = try self.child.wait(self.io);
        self.waited = true;
        return switch (term) {
            .exited => |code| .{ .exited = code },
            .signal, .stopped => |sig| if (comptime is_windows) .{ .unknown = 0 } else .{ .signal = @intFromEnum(sig) },
            .unknown => |status| .{ .unknown = status },
        };
    }

    /// Kills anything still running and releases everything. Call once, after `wait` or instead of it.
    pub fn deinit(self: *Running) void {
        if (!self.waited) {
            self.tree.signal(.kill);
            self.child.kill(self.io);
        }
        self.tree.deinit(self.io);
    }
};

/// Runs `script` with `root` as the working directory. `cwd` is `root` as a child process cwd.
pub fn spawn(io: std.Io, allocator: std.mem.Allocator, root: std.Io.Dir, cwd: std.process.Child.Cwd, script: []const u8) !Running {
    return if (is_windows)
        spawn_windows(io, allocator, root, cwd, script)
    else
        spawn_posix(io, allocator, cwd, script);
}

pub const ArgvOptions = struct {
    stdin: enum { ignore, pipe } = .ignore,
    stderr: enum { inherit, pipe } = .inherit,
};

/// Like `spawn_argv`, but the child's stderr is the same pipe as its stdout.
/// No shell: `cmd /c ... 2>&1` would reparse `&` and `^` in the command line.
pub fn spawn_merged_argv(
    io: std.Io,
    allocator: std.mem.Allocator,
    cwd: std.process.Child.Cwd,
    argv: []const []const u8,
    opts: ArgvOptions,
) !Running {
    return if (is_windows)
        spawn_merged_windows(io, allocator, cwd, argv, opts)
    else
        spawn_merged_posix(io, cwd, argv, opts);
}

/// Runs `argv` directly (no shell), in a process group / job so `Running.deinit` stops the tree.
/// `argv` is not copied; it only needs to live until this returns.
pub fn spawn_argv(
    io: std.Io,
    allocator: std.mem.Allocator,
    cwd: std.process.Child.Cwd,
    argv: []const []const u8,
    opts: ArgvOptions,
) !Running {
    return if (is_windows)
        spawn_argv_windows(io, allocator, cwd, argv, opts)
    else
        spawn_argv_posix(io, cwd, argv, opts);
}

/// Makes the server stop running commands before it exits.
pub fn stop_all_on_exit() void {
    // Windows: nothing to do, closing the server closes its job handles, which kills them.
    if (!is_windows) posix.stop_all_on_exit();
}

const Tree = if (is_windows) WindowsTree else PosixTree;
const Signal = enum { stop, kill };

// ---------------------------------------------------------------- POSIX

fn spawn_merged_posix(io: std.Io, cwd: std.process.Child.Cwd, argv: []const []const u8, opts: ArgvOptions) !Running {
    var fds: [2]std.posix.fd_t = undefined;
    switch (std.posix.errno(std.posix.system.pipe2(&fds, .{ .CLOEXEC = true }))) {
        .SUCCESS => {},
        else => return error.SystemResources,
    }
    const read_end: std.Io.File = .{ .handle = fds[0], .flags = .{ .nonblocking = false } };
    const write_end: std.Io.File = .{ .handle = fds[1], .flags = .{ .nonblocking = false } };
    errdefer read_end.close(io);
    errdefer write_end.close(io);

    // Both descriptors are dup2'd onto this one write end. CLOEXEC drops the original at exec.
    var child = try std.process.spawn(io, .{
        .argv = argv,
        .cwd = cwd,
        .stdin = if (opts.stdin == .pipe) .pipe else .ignore,
        .stdout = .{ .file = write_end },
        .stderr = .{ .file = write_end },
        .pgid = 0,
    });
    write_end.close(io);
    child.stdout = read_end;
    posix.track(child.id.?);
    return .{ .io = io, .child = child, .tree = .{ .pgid = child.id.? } };
}

fn spawn_argv_posix(io: std.Io, cwd: std.process.Child.Cwd, argv: []const []const u8, opts: ArgvOptions) !Running {
    const child = try std.process.spawn(io, .{
        .argv = argv,
        .cwd = cwd,
        .stdin = if (opts.stdin == .pipe) .pipe else .ignore,
        .stdout = .pipe,
        .stderr = if (opts.stderr == .pipe) .pipe else .inherit,
        .pgid = 0,
    });
    posix.track(child.id.?);
    return .{ .io = io, .child = child, .tree = .{ .pgid = child.id.? } };
}

fn spawn_posix(io: std.Io, allocator: std.mem.Allocator, cwd: std.process.Child.Cwd, script: []const u8) !Running {
    const full = try std.fmt.allocPrint(allocator, "exec 2>&1\n{s}", .{script});
    defer allocator.free(full);

    const child = try std.process.spawn(io, .{
        .argv = &.{ "sh", "-c", full },
        .cwd = cwd,
        .stdin = .ignore,
        .stdout = .pipe,
        // Own process group, so stopping it also stops whatever it started (e.g. a dev server).
        .pgid = 0,
    });
    posix.track(child.id.?);
    return .{ .io = io, .child = child, .tree = .{ .pgid = child.id.? } };
}

const PosixTree = struct {
    pgid: std.posix.pid_t,

    fn signal(self: PosixTree, how: Signal) void {
        posix.kill_group(self.pgid, if (how == .stop) .TERM else .KILL);
    }

    fn deinit(self: PosixTree, io: std.Io) void {
        _ = io;
        posix.untrack(self.pgid);
    }
};

const posix = if (is_windows) struct {} else struct {
    /// Process groups of running commands, read from a signal handler, so fixed size and lock free.
    var groups = [_]std.atomic.Value(std.posix.pid_t){.init(0)} ** 64;

    fn track(pgid: std.posix.pid_t) void {
        for (&groups) |*slot| {
            if (slot.cmpxchgStrong(0, pgid, .acq_rel, .monotonic) == null) return;
        }
        std.log.warn("rmt: too many commands running, pid {d} won't be stopped if the server exits", .{pgid});
    }

    fn untrack(pgid: std.posix.pid_t) void {
        for (&groups) |*slot| {
            if (slot.cmpxchgStrong(pgid, 0, .acq_rel, .monotonic) == null) return;
        }
    }

    fn kill_group(pgid: std.posix.pid_t, sig: std.posix.SIG) void {
        std.posix.kill(-pgid, sig) catch {};
    }

    /// Commands run in their own process groups, so they'd outlive `rmtbuild serve`.
    /// Ctrl-C / SIGTERM / SIGHUP on the server stops them first.
    fn stop_all_on_exit() void {
        const act: std.posix.Sigaction = .{
            .handler = .{ .handler = on_exit_signal },
            .mask = std.posix.sigemptyset(),
            .flags = 0,
        };
        std.posix.sigaction(.INT, &act, null);
        std.posix.sigaction(.TERM, &act, null);
        std.posix.sigaction(.HUP, &act, null);
    }

    fn on_exit_signal(sig: std.posix.SIG) callconv(.c) void {
        for (&groups) |*slot| {
            const pgid = slot.load(.acquire);
            if (pgid != 0) kill_group(pgid, .TERM);
        }
        // Then exit the way the signal would have without us.
        const default: std.posix.Sigaction = .{
            .handler = .{ .handler = std.posix.SIG.DFL },
            .mask = std.posix.sigemptyset(),
            .flags = 0,
        };
        std.posix.sigaction(sig, &default, null);
        std.posix.raise(sig) catch {};
    }
};

// ---------------------------------------------------------------- Windows

fn spawn_windows(io: std.Io, allocator: std.mem.Allocator, root: std.Io.Dir, cwd: std.process.Child.Cwd, script: []const u8) !Running {
    // The script goes in a batch file because cmd /c only takes one line. It lives in .git (falling
    // back to the repo root when .git is a file, e.g. a worktree) and is referenced by a relative path:
    // cmd.exe would misparse an absolute path with `&` or `^` in it, like a temp dir under "C:\Users\R&D".
    var rand: [8]u8 = undefined;
    io.random(&rand);
    const name = std.fmt.bytesToHex(rand, .lower);

    var path: []u8 = try std.fmt.allocPrint(allocator, ".git\\rmtbuild-run-{s}.cmd", .{name});
    errdefer allocator.free(path);

    const contents = try batch_file(allocator, script);
    defer allocator.free(contents);

    root.writeFile(io, .{ .sub_path = path, .data = contents, .flags = .{ .exclusive = true } }) catch |err| switch (err) {
        error.FileNotFound, error.NotDir => {
            allocator.free(path);
            path = try std.fmt.allocPrint(allocator, ".rmtbuild-run-{s}.cmd", .{name});
            try root.writeFile(io, .{ .sub_path = path, .data = contents, .flags = .{ .exclusive = true } });
        },
        else => return err,
    };
    errdefer root.deleteFile(io, path) catch {};

    const job = try create_kill_job();
    errdefer std.os.windows.CloseHandle(job);

    var child = try std.process.spawn(io, .{
        // /d skips AutoRun registry commands. "2>&1" applies to the whole batch file.
        .argv = &.{ "cmd.exe", "/d", "/c", path, "2>&1" },
        .cwd = cwd,
        .stdin = .ignore,
        .stdout = .pipe,
        // Suspended until it's in the job, so nothing it starts can escape the job.
        .start_suspended = true,
    });
    errdefer child.kill(io);

    if (!win.AssignProcessToJobObject(job, child.id.?).toBool()) return error.JobObjectFailed;
    if (win.ResumeThread(child.thread_handle) == std.math.maxInt(u32)) return error.ResumeFailed;

    return .{ .io = io, .child = child, .tree = .{ .job = job, .root = root, .script = path, .allocator = allocator } };
}

fn spawn_merged_windows(
    io: std.Io,
    allocator: std.mem.Allocator,
    cwd: std.process.Child.Cwd,
    argv: []const []const u8,
    opts: ArgvOptions,
) !Running {
    const windows = std.os.windows;
    const job = try create_kill_job();
    errdefer windows.CloseHandle(job);

    // One inheritable write end, used for both stdout and stderr. The read end stays private.
    var sa = windows.SECURITY_ATTRIBUTES{
        .nLength = @sizeOf(windows.SECURITY_ATTRIBUTES),
        .lpSecurityDescriptor = null,
        .bInheritHandle = windows.BOOL.TRUE,
    };
    var read_out: windows.HANDLE = undefined;
    var write_out: windows.HANDLE = undefined;
    if (!win.CreatePipe(&read_out, &write_out, &sa, 0).toBool()) return error.SystemResources;
    var close_read_out = true;
    var close_write_out = true;
    errdefer if (close_read_out) windows.CloseHandle(read_out);
    errdefer if (close_write_out) windows.CloseHandle(write_out);
    if (!win.SetHandleInformation(read_out, win.HANDLE_FLAG_INHERIT, 0).toBool()) return error.SystemResources;

    var read_in: ?windows.HANDLE = null;
    var write_in: ?windows.HANDLE = null;
    if (opts.stdin == .pipe) {
        var r: windows.HANDLE = undefined;
        var w: windows.HANDLE = undefined;
        if (!win.CreatePipe(&r, &w, &sa, 0).toBool()) return error.SystemResources;
        errdefer windows.CloseHandle(r);
        errdefer windows.CloseHandle(w);
        if (!win.SetHandleInformation(w, win.HANDLE_FLAG_INHERIT, 0).toBool()) return error.SystemResources;
        read_in = r;
        write_in = w;
    }
    const nul = if (read_in == null) win.CreateFileW(
        std.unicode.utf8ToUtf16LeStringLiteral("NUL"),
        win.GENERIC_READ,
        win.FILE_SHARE_READ | win.FILE_SHARE_WRITE,
        &sa,
        win.OPEN_EXISTING,
        0,
        null,
    ) else null;
    if (nul) |handle| {
        if (handle == windows.INVALID_HANDLE_VALUE) return error.SystemResources;
    }
    defer if (nul) |handle| windows.CloseHandle(handle);

    const cmdline_src: []const []const u8 = if (argv.len != 0 and is_batch_name(argv[0]))
        // A .cmd/.bat is not a process. One cmd.exe, no `2>&1` text, stderr is the shared pipe.
        try std.mem.concat(allocator, []const u8, &.{ &.{ "cmd.exe", "/d", "/c" }, argv })
    else
        argv;
    defer if (cmdline_src.ptr != argv.ptr) allocator.free(cmdline_src);

    const command_line = try argv_to_command_line(allocator, cmdline_src);
    defer allocator.free(command_line);
    const cwd_w = try windows_cwd(allocator, cwd);
    defer if (cwd_w) |p| allocator.free(p);

    var si = std.mem.zeroes(windows.STARTUPINFOW);
    si.cb = @sizeOf(windows.STARTUPINFOW);
    si.dwFlags = windows.STARTF_USESTDHANDLES;
    si.hStdInput = read_in orelse nul;
    si.hStdOutput = write_out;
    si.hStdError = write_out;

    var pi: windows.PROCESS.INFORMATION = undefined;
    const created = windows.kernel32.CreateProcessW(
        null,
        command_line.ptr,
        null,
        null,
        windows.BOOL.TRUE,
        .{ .create_suspended = true },
        null,
        if (cwd_w) |p| p.ptr else null,
        &si,
        &pi,
    );
    if (!created.toBool()) {
        if (read_in) |handle| windows.CloseHandle(handle);
        if (write_in) |handle| windows.CloseHandle(handle);
        const err = windows.GetLastError();
        if (err == .FILE_NOT_FOUND or err == .PATH_NOT_FOUND) return error.FileNotFound;
        return error.Unexpected;
    }
    errdefer {
        _ = win.TerminateProcess(pi.hProcess, 1);
        windows.CloseHandle(pi.hThread);
        windows.CloseHandle(pi.hProcess);
    }
    // Parent copies. The child inherited the write end for both stdout and stderr.
    windows.CloseHandle(write_out);
    close_write_out = false;
    if (read_in) |handle| windows.CloseHandle(handle);

    if (!win.AssignProcessToJobObject(job, pi.hProcess).toBool()) return error.JobObjectFailed;
    if (win.ResumeThread(pi.hThread) == std.math.maxInt(u32)) return error.ResumeFailed;

    const stdin_file: ?std.Io.File = if (write_in) |handle| .{ .handle = handle, .flags = .{ .nonblocking = false } } else null;
    close_read_out = false;
    return .{
        .io = io,
        .child = .{
            .id = if (comptime is_windows) pi.hProcess else unreachable,
            .thread_handle = if (comptime is_windows) pi.hThread else unreachable,
            .stdin = stdin_file,
            .stdout = .{ .handle = read_out, .flags = .{ .nonblocking = true } },
            .stderr = null,
            .request_resource_usage_statistics = false,
        },
        .tree = .{ .job = job, .root = std.Io.Dir.cwd(), .script = null, .allocator = allocator },
    };
}

fn is_batch_name(path: []const u8) bool {
    return std.ascii.endsWithIgnoreCase(path, ".cmd") or std.ascii.endsWithIgnoreCase(path, ".bat");
}

fn windows_cwd(allocator: std.mem.Allocator, cwd: std.process.Child.Cwd) !?[:0]u16 {
    switch (cwd) {
        .inherit => return null,
        .path => |path| return try std.unicode.wtf8ToWtf16LeAllocZ(allocator, path),
        .dir => |dir| {
            var buf: [4096]u16 = undefined;
            const path = try std.Io.Threaded.GetFinalPathNameByHandle(dir.handle, .{ .volume_name = .Dos }, &buf);
            return try allocator.dupeZ(u16, path);
        },
    }
}

/// CreateProcess command line. Same quoting rules the Zig runtime uses, so `&` and `^` stay data.
fn argv_to_command_line(allocator: std.mem.Allocator, argv: []const []const u8) ![:0]u16 {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);
    if (argv.len != 0) {
        const arg0 = argv[0];
        var needs_quotes = arg0.len == 0;
        for (arg0) |c| {
            if (c <= ' ') needs_quotes = true else if (c == '"') return error.InvalidArg0;
        }
        if (needs_quotes) {
            try buf.append(allocator, '"');
            try buf.appendSlice(allocator, arg0);
            try buf.append(allocator, '"');
        } else try buf.appendSlice(allocator, arg0);

        for (argv[1..]) |arg| {
            try buf.append(allocator, ' ');
            const quote = for (arg) |c| {
                if (c <= ' ' or c == '"') break true;
            } else arg.len == 0;
            if (!quote) {
                try buf.appendSlice(allocator, arg);
                continue;
            }
            try buf.append(allocator, '"');
            var backslashes: usize = 0;
            for (arg) |byte| switch (byte) {
                '\\' => backslashes += 1,
                '"' => {
                    try buf.appendNTimes(allocator, '\\', backslashes * 2 + 1);
                    try buf.append(allocator, '"');
                    backslashes = 0;
                },
                else => {
                    try buf.appendNTimes(allocator, '\\', backslashes);
                    try buf.append(allocator, byte);
                    backslashes = 0;
                },
            };
            try buf.appendNTimes(allocator, '\\', backslashes * 2);
            try buf.append(allocator, '"');
        }
    }
    return try std.unicode.wtf8ToWtf16LeAllocZ(allocator, buf.items);
}

fn spawn_argv_windows(
    io: std.Io,
    allocator: std.mem.Allocator,
    cwd: std.process.Child.Cwd,
    argv: []const []const u8,
    opts: ArgvOptions,
) !Running {
    const job = try create_kill_job();
    errdefer std.os.windows.CloseHandle(job);

    var child = try std.process.spawn(io, .{
        .argv = argv,
        .cwd = cwd,
        .stdin = if (opts.stdin == .pipe) .pipe else .ignore,
        .stdout = .pipe,
        .stderr = if (opts.stderr == .pipe) .pipe else .inherit,
        .start_suspended = true,
    });
    errdefer child.kill(io);

    if (!win.AssignProcessToJobObject(job, child.id.?).toBool()) return error.JobObjectFailed;
    if (win.ResumeThread(child.thread_handle) == std.math.maxInt(u32)) return error.ResumeFailed;

    return .{
        .io = io,
        .child = child,
        .tree = .{ .job = job, .root = std.Io.Dir.cwd(), .script = null, .allocator = allocator },
    };
}

fn create_kill_job() !std.os.windows.HANDLE {
    const job = win.CreateJobObjectW(null, null) orelse return error.JobObjectFailed;
    errdefer std.os.windows.CloseHandle(job);

    var limits = std.mem.zeroes(win.JOBOBJECT_EXTENDED_LIMIT_INFORMATION);
    limits.BasicLimitInformation.LimitFlags = win.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!win.SetInformationJobObject(job, win.JobObjectExtendedLimitInformation, &limits, @sizeOf(@TypeOf(limits))).toBool())
        return error.JobObjectFailed;
    return job;
}

/// `@echo off` so commands aren't echoed (like sh), and CRLF line endings because cmd's labels and
/// `goto` misbehave with bare LF.
fn batch_file(allocator: std.mem.Allocator, script: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.appendSlice(allocator, "@echo off\r\n");
    for (script, 0..) |c, i| {
        if (c == '\n' and (i == 0 or script[i - 1] != '\r')) try out.append(allocator, '\r');
        try out.append(allocator, c);
    }
    if (out.items[out.items.len - 1] != '\n') try out.appendSlice(allocator, "\r\n");
    return out.toOwnedSlice(allocator);
}

const WindowsTree = struct {
    job: std.os.windows.HANDLE,
    root: std.Io.Dir,
    /// Batch file to delete, when the tree was started from a script rather than `spawn_argv`.
    script: ?[]u8,
    allocator: std.mem.Allocator,

    fn signal(self: WindowsTree, how: Signal) void {
        _ = how;
        _ = win.TerminateJobObject(self.job, 1);
    }

    fn deinit(self: WindowsTree, io: std.Io) void {
        // Kills anything the command left running (KILL_ON_JOB_CLOSE).
        std.os.windows.CloseHandle(self.job);
        if (self.script) |script| {
            self.root.deleteFile(io, script) catch {};
            self.allocator.free(script);
        }
    }
};

/// Job Object API, not in std.
const win = struct {
    const windows = std.os.windows;
    const BOOL = windows.BOOL;
    const DWORD = windows.DWORD;
    const HANDLE = windows.HANDLE;

    const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: DWORD = 0x2000;
    const JobObjectExtendedLimitInformation: c_int = 9;

    const JOBOBJECT_BASIC_LIMIT_INFORMATION = extern struct {
        PerProcessUserTimeLimit: windows.LARGE_INTEGER,
        PerJobUserTimeLimit: windows.LARGE_INTEGER,
        LimitFlags: DWORD,
        MinimumWorkingSetSize: windows.SIZE_T,
        MaximumWorkingSetSize: windows.SIZE_T,
        ActiveProcessLimit: DWORD,
        Affinity: windows.ULONG_PTR,
        PriorityClass: DWORD,
        SchedulingClass: DWORD,
    };

    const IO_COUNTERS = extern struct {
        ReadOperationCount: u64,
        WriteOperationCount: u64,
        OtherOperationCount: u64,
        ReadTransferCount: u64,
        WriteTransferCount: u64,
        OtherTransferCount: u64,
    };

    const JOBOBJECT_EXTENDED_LIMIT_INFORMATION = extern struct {
        BasicLimitInformation: JOBOBJECT_BASIC_LIMIT_INFORMATION,
        IoInfo: IO_COUNTERS,
        ProcessMemoryLimit: windows.SIZE_T,
        JobMemoryLimit: windows.SIZE_T,
        PeakProcessMemoryUsed: windows.SIZE_T,
        PeakJobMemoryUsed: windows.SIZE_T,
    };

    comptime {
        // Matches the Windows SDK layout on 64-bit.
        if (@sizeOf(usize) == 8) std.debug.assert(@sizeOf(JOBOBJECT_EXTENDED_LIMIT_INFORMATION) == 144);
    }

    const HANDLE_FLAG_INHERIT: DWORD = 0x00000001;
    const GENERIC_READ: DWORD = 0x80000000;
    const FILE_SHARE_READ: DWORD = 0x00000001;
    const FILE_SHARE_WRITE: DWORD = 0x00000002;
    const OPEN_EXISTING: DWORD = 3;

    extern "kernel32" fn CreateJobObjectW(attributes: ?*windows.SECURITY_ATTRIBUTES, name: ?windows.LPCWSTR) callconv(.winapi) ?HANDLE;
    extern "kernel32" fn SetInformationJobObject(job: HANDLE, class: c_int, info: *anyopaque, len: DWORD) callconv(.winapi) BOOL;
    extern "kernel32" fn AssignProcessToJobObject(job: HANDLE, process: HANDLE) callconv(.winapi) BOOL;
    extern "kernel32" fn TerminateJobObject(job: HANDLE, exit_code: windows.UINT) callconv(.winapi) BOOL;
    extern "kernel32" fn TerminateProcess(process: HANDLE, exit_code: windows.UINT) callconv(.winapi) BOOL;
    extern "kernel32" fn ResumeThread(thread: HANDLE) callconv(.winapi) DWORD;
    extern "kernel32" fn CreatePipe(read: *HANDLE, write: *HANDLE, sa: ?*windows.SECURITY_ATTRIBUTES, size: DWORD) callconv(.winapi) BOOL;
    extern "kernel32" fn SetHandleInformation(handle: HANDLE, mask: DWORD, flags: DWORD) callconv(.winapi) BOOL;
    extern "kernel32" fn CreateFileW(
        name: [*:0]const u16,
        access: DWORD,
        share: DWORD,
        sa: ?*windows.SECURITY_ATTRIBUTES,
        disposition: DWORD,
        flags: DWORD,
        template: ?HANDLE,
    ) callconv(.winapi) HANDLE;
    extern "kernel32" fn SetNamedPipeHandleState(handle: HANDLE, mode: ?*DWORD, max_collect: ?*DWORD, timeout: ?*DWORD) callconv(.winapi) BOOL;
    extern "kernel32" fn WriteFile(handle: HANDLE, buf: [*]const u8, len: DWORD, written: *DWORD, overlapped: ?*anyopaque) callconv(.winapi) BOOL;
};

test "batch file conversion" {
    const out = try batch_file(std.testing.allocator, "echo a\nif 1==1 (\n  echo b\r\n)");
    defer std.testing.allocator.free(out);
    try std.testing.expectEqualStrings("@echo off\r\necho a\r\nif 1==1 (\r\n  echo b\r\n)\r\n", out);
}

test "spawn_argv" {
    const io = std.testing.io;
    const argv: []const []const u8 = if (is_windows)
        &.{ "cmd.exe", "/d", "/c", "echo hi" }
    else
        &.{ "echo", "hi" };

    var running = try spawn_argv(io, std.testing.allocator, .inherit, argv, .{});
    defer running.deinit();

    var buf: [64]u8 = undefined;
    var reader = running.output().reader(io, &buf);
    var out: [64]u8 = undefined;
    const n = try reader.interface.readSliceShort(&out);
    const expected = if (is_windows) "hi\r\n" else "hi\n";
    try std.testing.expectEqualStrings(expected, out[0..n]);
    try std.testing.expectEqual(Exit{ .exited = 0 }, try running.wait());
}

test "spawn, output and exit code" {
    const io = std.testing.io;
    const script = if (is_windows) "echo out\necho err 1>&2\nexit /b 3" else "echo out\necho err 1>&2\nexit 3";

    var running = try spawn(io, std.testing.allocator, std.Io.Dir.cwd(), .inherit, script);
    defer running.deinit();

    var buf: [256]u8 = undefined;
    var reader = running.output().reader(io, &buf);
    var out: [256]u8 = undefined;
    const n = try reader.interface.readSliceShort(&out);

    const expected = if (is_windows) "out\r\nerr \r\n" else "out\nerr\n";
    try std.testing.expectEqualStrings(expected, out[0..n]);
    try std.testing.expectEqual(Exit{ .exited = 3 }, try running.wait());
}
