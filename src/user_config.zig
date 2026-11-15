//! The user's own settings, `config.yaml` next to the key (see `auth.config_file_path`).
//! `rmtbuild keygen` writes the first one.
//!
//! Which server to talk to differs per person, so it lives here and not in the repo's
//! `rmtbuild.yaml`, which keeps the commands everyone shares.
//!
//! ```yaml
//! server:                  # every directory without an entry below
//!   address: 192.168.1.20  # where the client connects
//!   port: 8099
//!   listen: 0.0.0.0        # where `rmtbuild serve` binds, default 127.0.0.1
//!   max_payload_mb: 256    # largest file `rmtbuild serve` accepts, default 256
//! directories:
//!   ~/work/app:            # this directory and everything below it
//!     address: 10.0.0.5
//!     port: 9000
//! ```
//!
//! The server is picked in this order, and the one picked is used whole: keys it leaves out
//! take the built-in defaults, not the values of the next one down.
//!
//!   1. the `directories` entry the current directory is in, the longest path if several match
//!   2. `server` in this file
//!   3. `server` in the repo's `rmtbuild.yaml`
//!   4. the built-in defaults, 127.0.0.1:8099
const std = @import("std");
const builtin = @import("builtin");
const config = @import("config.zig");
const Allocator = std.mem.Allocator;
const Os = std.Target.Os.Tag;

pub const file_name = "config.yaml";

pub const Directory = struct {
    /// As written in the file, for messages.
    name: []const u8,
    /// Absolute, with `~`, `.`, `..` and trailing separators resolved.
    path: []const u8,
    /// `path` with symlinks followed, when that is somewhere else. Filled in by `load`.
    real: ?[]const u8 = null,
    server: config.Server,
};

pub const UserConfig = struct {
    /// The fallback, for directories with no entry of their own.
    server: ?config.Server = null,
    /// In file order.
    directories: []Directory = &.{},

    /// Everything is allocated in `arena`. `home` is what a leading `~` stands for.
    pub fn parse(arena: Allocator, text: []const u8, os: Os, home: ?[]const u8, diag: *config.Diagnostic) !UserConfig {
        const root = try config.parse_yaml(arena, text, diag);

        var result: UserConfig = .{};
        var it = root.iterator();
        while (it.next()) |entry| {
            const key = entry.key_ptr.*;
            if (std.mem.eql(u8, key, "server")) {
                if (!config.is_empty(entry.value_ptr.*)) result.server = try config.Server.parse(arena, entry.value_ptr.*, "server", diag);
            } else if (std.mem.eql(u8, key, "directories")) {
                result.directories = try parse_directories(arena, entry.value_ptr.*, os, home, diag);
            } else if (std.mem.eql(u8, key, "commands")) {
                return config.fail_fmt(arena, diag, "'commands' go in the repo's " ++ config.file_name ++ ", this file only has 'server' and 'directories'", .{});
            } else {
                return config.fail_fmt(arena, diag, "unknown key '{s}', expected 'server' or 'directories'", .{key});
            }
        }
        return result;
    }

    /// Reads the file at `path`. `error.FileNotFound` if there isn't one.
    pub fn load(arena: Allocator, io: std.Io, path: []const u8, home: ?[]const u8, diag: *config.Diagnostic) !UserConfig {
        const text = try std.Io.Dir.cwd().readFileAlloc(io, path, arena, .limited(1024 * 1024));
        const result = try parse(arena, text, builtin.os.tag, home, diag);
        for (result.directories) |*dir| dir.real = real_path(arena, io, dir.path);
        return result;
    }

    /// The entry `here` is in. `here` holds the same directory spelled one or more ways
    /// (as the shell has it, with symlinks followed), each absolute and resolved.
    pub fn find(self: UserConfig, os: Os, here: []const []const u8) ?*const Directory {
        var best: ?*const Directory = null;
        var best_len: usize = 0;
        for (self.directories) |*dir| {
            for ([_]?[]const u8{ dir.path, dir.real }) |spelling| {
                const path = spelling orelse continue;
                for (here) |current| {
                    if (!within(os, path, current)) continue;
                    // The deepest directory is the most specific one.
                    if (best == null or path.len > best_len) {
                        best = dir;
                        best_len = path.len;
                    }
                }
            }
        }
        return best;
    }

    /// The entry the process's current directory is in.
    pub fn find_here(self: UserConfig, arena: Allocator, io: std.Io) !?*const Directory {
        if (self.directories.len == 0) return null;
        const os = builtin.os.tag;
        const cwd = try resolve(arena, os, try std.process.currentPathAlloc(io, arena));
        const real = real_path(arena, io, cwd) orelse return self.find(os, &.{cwd});
        return self.find(os, &.{ cwd, real });
    }
};

fn parse_directories(arena: Allocator, node: config.Node, os: Os, home: ?[]const u8, diag: *config.Diagnostic) ![]Directory {
    const map = try config.expect_map(arena, node, "directories", diag);
    var list: std.ArrayList(Directory) = .empty;

    var it = map.iterator();
    while (it.next()) |entry| {
        const name = entry.key_ptr.*;
        const path = try expand(arena, os, home, name, diag);
        for (list.items) |existing| {
            if (same_path(os, existing.path, path))
                return config.fail_fmt(arena, diag, "directories: '{s}' and '{s}' are the same directory", .{ existing.name, name });
        }

        const label = try std.fmt.allocPrint(arena, "directories[{s}]", .{name});
        try list.append(arena, .{
            .name = name,
            .path = path,
            .server = try config.Server.parse(arena, entry.value_ptr.*, label, diag),
        });
    }
    return list.items;
}

/// Turns a `directories` key into an absolute, resolved path.
fn expand(arena: Allocator, os: Os, home: ?[]const u8, name: []const u8, diag: *config.Diagnostic) ![]const u8 {
    var text = name;
    if (text.len != 0 and text[0] == '~' and (text.len == 1 or is_sep(os, text[1]))) {
        const dir = home orelse
            return config.fail_fmt(arena, diag, "directories: can't expand '~' in '{s}', {s} isn't set", .{ name, home_env(os) });
        text = try std.fmt.allocPrint(arena, "{s}{s}", .{ dir, text[1..] });
    }

    const absolute = if (os == .windows) is_absolute_windows(text) else std.fs.path.isAbsolutePosix(text);
    if (!absolute) {
        const example = if (os == .windows) "C:\\Users\\me\\app" else "/home/me/app";
        return config.fail_fmt(arena, diag, "directories: '{s}' should be a full path like '{s}', or start with '~'", .{ name, example });
    }
    return resolve(arena, os, text);
}

/// `C:\...` or `\\server\share\...`. A path with a root but no drive (`\app`) depends on the
/// current drive, so it doesn't count.
fn is_absolute_windows(text: []const u8) bool {
    const kind = std.fs.path.getWin32PathType(u8, text);
    return kind == .drive_absolute or kind == .unc_absolute;
}

fn resolve(arena: Allocator, os: Os, path: []const u8) ![]const u8 {
    return if (os == .windows) std.fs.path.resolveWindows(arena, &.{path}) else std.fs.path.resolvePosix(arena, &.{path});
}

/// Where `path` leads once symlinks are followed. Null when that is `path` itself, or it
/// can't be found out (the directory doesn't exist here).
fn real_path(arena: Allocator, io: std.Io, path: []const u8) ?[]const u8 {
    const real = std.Io.Dir.realPathFileAbsoluteAlloc(io, path, arena) catch return null;
    return if (std.mem.eql(u8, real, path)) null else real;
}

fn is_sep(os: Os, byte: u8) bool {
    return byte == '/' or (os == .windows and byte == '\\');
}

fn same_path(os: Os, a: []const u8, b: []const u8) bool {
    // Windows file names ignore case.
    return if (os == .windows) std.ascii.eqlIgnoreCase(a, b) else std.mem.eql(u8, a, b);
}

/// Whether `path` is `dir` or somewhere below it. Both are absolute and resolved.
fn within(os: Os, dir: []const u8, path: []const u8) bool {
    if (dir.len == 0 or path.len < dir.len) return false;
    if (!same_path(os, dir, path[0..dir.len])) return false;
    if (path.len == dir.len) return true;
    // `/app` holds `/app/src` but not `/application`. Roots (`/`, `C:\`) end in a separator.
    return is_sep(os, dir[dir.len - 1]) or is_sep(os, path[dir.len]);
}

fn home_env(os: Os) []const u8 {
    return if (os == .windows) "USERPROFILE" else "HOME";
}

/// What a leading `~` in a `directories` key stands for.
pub fn home_dir(environ: *const std.process.Environ.Map) ?[]const u8 {
    const home = environ.get(home_env(builtin.os.tag)) orelse return null;
    return if (home.len == 0) null else home;
}

/// The file `rmtbuild keygen` writes: `address` and `port` as the fallback server, the rest
/// as comments to edit.
pub fn template(arena: Allocator, address: []const u8, port: u16) ![]u8 {
    return std.fmt.allocPrint(arena,
        \\# rmtbuild settings for this user on this machine.
        \\# Commands are shared and stay in each repo's rmtbuild.yaml.
        \\
        \\# The server for every directory that has no entry under 'directories'.
        \\server:
        \\  address: {s}  # the build machine, where `rmtbuild <command>` connects
        \\  port: {d}
        \\  # listen: 0.0.0.0      # where `rmtbuild serve` binds, default 127.0.0.1
        \\  # max_payload_mb: 256  # largest file `rmtbuild serve` accepts
        \\
        \\# A server for one directory and everything below it. The longest matching path
        \\# wins. An entry is used whole: keys it leaves out take the defaults
        \\# (127.0.0.1, 8099), not the values from 'server' above.
        \\#
        \\# directories:
        \\#   ~/work/app:
        \\#     address: 192.168.1.20
        \\#     port: 8099
        \\
    , .{ address, port });
}

/// Writes a new file at `path`, making parent directories as needed.
/// `error.PathAlreadyExists` if there is one already, which is left alone.
pub fn write_new(io: std.Io, path: []const u8, text: []const u8) !void {
    const cwd = std.Io.Dir.cwd();
    if (std.fs.path.dirname(path)) |dir| try cwd.createDirPath(io, dir);
    try cwd.writeFile(io, .{ .sub_path = path, .data = text, .flags = .{ .exclusive = true } });
}

fn test_parse(arena: Allocator, text: []const u8, os: Os, home: ?[]const u8) !UserConfig {
    var diag: config.Diagnostic = .{};
    return UserConfig.parse(arena, text, os, home, &diag) catch |err| {
        std.debug.print("unexpected config error: {f}\n", .{diag});
        return err;
    };
}

fn expect_error(text: []const u8, os: Os, home: ?[]const u8, message_part: []const u8) !void {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var diag: config.Diagnostic = .{};
    try std.testing.expectError(error.InvalidConfig, UserConfig.parse(arena.allocator(), text, os, home, &diag));
    if (std.mem.indexOf(u8, diag.message, message_part) == null) {
        std.debug.print("expected '{s}' in '{s}'\n", .{ message_part, diag.message });
        return error.TestUnexpectedResult;
    }
}

test "UserConfig parse" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const user = try test_parse(arena.allocator(),
        \\server:
        \\  address: 192.168.1.20
        \\  port: 9000
        \\  listen: 0.0.0.0
        \\  max_payload_mb: 64
        \\directories:
        \\  /home/me/work/app/:
        \\    address: 10.0.0.5
        \\  ~/other/../side:
        \\    address: 10.0.0.6
        \\    port: 9001
        \\  '/srv/odd: name #1':
        \\    port: 9002
        \\
    , .linux, "/home/me");

    const fallback = user.server.?;
    try std.testing.expectEqualStrings("192.168.1.20", fallback.address);
    try std.testing.expectEqual(9000, fallback.port);
    try std.testing.expectEqualStrings("0.0.0.0", fallback.listen);
    try std.testing.expectEqual(64, fallback.max_payload_mb);

    try std.testing.expectEqual(3, user.directories.len);
    const app = user.directories[0];
    try std.testing.expectEqualStrings("/home/me/work/app/", app.name);
    try std.testing.expectEqualStrings("/home/me/work/app", app.path);
    try std.testing.expectEqualStrings("10.0.0.5", app.server.address);
    // An entry is used whole, so this is the default port and not the fallback's 9000.
    try std.testing.expectEqual(8099, app.server.port);

    try std.testing.expectEqualStrings("/home/me/side", user.directories[1].path);
    try std.testing.expectEqual(9001, user.directories[1].server.port);
    try std.testing.expectEqualStrings("/srv/odd: name #1", user.directories[2].path);

    const empty = try test_parse(arena.allocator(), "# nothing yet\nserver:\n  # address: 10.0.0.1\n", .linux, null);
    try std.testing.expect(empty.server == null);
    try std.testing.expectEqual(0, empty.directories.len);
}

test "UserConfig find" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const user = try test_parse(arena.allocator(),
        \\directories:
        \\  /home/me/work:
        \\    address: 10.0.0.1
        \\  /home/me/work/app:
        \\    address: 10.0.0.2
        \\  /data/link:
        \\    address: 10.0.0.3
        \\
    , .linux, null);
    // What `load` records for a symlinked directory.
    user.directories[2].real = "/mnt/disk/real";

    try std.testing.expectEqualStrings("10.0.0.1", user.find(.linux, &.{"/home/me/work"}).?.server.address);
    try std.testing.expectEqualStrings("10.0.0.1", user.find(.linux, &.{"/home/me/work/other/src"}).?.server.address);
    // The longest match, whatever the order in the file.
    try std.testing.expectEqualStrings("10.0.0.2", user.find(.linux, &.{"/home/me/work/app"}).?.server.address);
    try std.testing.expectEqualStrings("10.0.0.2", user.find(.linux, &.{"/home/me/work/app/src"}).?.server.address);
    // A longer name isn't a subdirectory.
    try std.testing.expectEqualStrings("10.0.0.1", user.find(.linux, &.{"/home/me/work/application"}).?.server.address);
    try std.testing.expect(user.find(.linux, &.{"/home/me/workshop"}) == null);
    try std.testing.expect(user.find(.linux, &.{"/home/me"}) == null);
    try std.testing.expect(user.find(.linux, &.{"/home/ME/work"}) == null);

    // Through the symlink, by either spelling of where we are.
    try std.testing.expectEqualStrings("10.0.0.3", user.find(.linux, &.{"/mnt/disk/real/src"}).?.server.address);
    try std.testing.expectEqualStrings("10.0.0.3", user.find(.linux, &.{ "/elsewhere", "/data/link" }).?.server.address);

    const root = try test_parse(arena.allocator(), "directories:\n  /:\n    address: 10.0.0.9\n", .linux, null);
    try std.testing.expectEqualStrings("10.0.0.9", root.find(.linux, &.{"/anything/at/all"}).?.server.address);
}

test "UserConfig Windows paths" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const user = try test_parse(arena.allocator(),
        \\directories:
        \\  C:\Users\me\work\:
        \\    address: 10.0.0.1
        \\  ~/work/app:
        \\    address: 10.0.0.2
        \\  D:\:
        \\    address: 10.0.0.3
        \\
    , .windows, "C:\\Users\\me");

    try std.testing.expectEqualStrings("C:\\Users\\me\\work", user.directories[0].path);
    try std.testing.expectEqualStrings("C:\\Users\\me\\work\\app", user.directories[1].path);

    try std.testing.expectEqualStrings("10.0.0.1", user.find(.windows, &.{"C:\\Users\\me\\work\\other"}).?.server.address);
    // Case doesn't matter on Windows.
    try std.testing.expectEqualStrings("10.0.0.2", user.find(.windows, &.{"c:\\users\\ME\\work\\App\\src"}).?.server.address);
    try std.testing.expectEqualStrings("10.0.0.3", user.find(.windows, &.{"D:\\build"}).?.server.address);
    try std.testing.expect(user.find(.windows, &.{"C:\\Users\\me\\workshop"}) == null);
}

test "UserConfig errors" {
    try expect_error("servers:\n  port: 1\n", .linux, null, "unknown key 'servers'");
    try expect_error("commands:\n  build:\n    run: x\n", .linux, null, "go in the repo's rmtbuild.yaml");
    try expect_error("server:\n  port: 70000\n", .linux, null, "server.port");
    try expect_error("server:\n  prot: 1\n", .linux, null, "unknown key 'prot'");
    try expect_error("directories:\n  /a:\n    port: x\n", .linux, null, "directories[/a].port");
    try expect_error("directories:\n  /a: 10.0.0.1\n", .linux, null, "expected nested keys");
    try expect_error("directories:\n  work/app:\n    port: 1\n", .linux, null, "should be a full path");
    try expect_error("directories:\n  ~/app:\n    port: 1\n", .linux, null, "HOME isn't set");
    try expect_error("directories:\n  ~me/app:\n    port: 1\n", .linux, "/home/me", "should be a full path");
    try expect_error("directories:\n  /a/b:\n    port: 1\n  /a/c/../b/:\n    port: 2\n", .linux, null, "same directory");
    try expect_error("directories:\n  \\app:\n    port: 1\n", .windows, null, "should be a full path");
    try expect_error("directories:\n  C:\\App:\n    port: 1\n  c:\\app\\:\n    port: 2\n", .windows, null, "same directory");
}

test "UserConfig template" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const text = try template(a, "192.168.1.20", 9000);
    const user = try test_parse(a, text, .linux, "/home/me");
    try std.testing.expectEqualStrings("192.168.1.20", user.server.?.address);
    try std.testing.expectEqual(9000, user.server.?.port);
    try std.testing.expectEqualStrings("127.0.0.1", user.server.?.listen);
    try std.testing.expectEqual(0, user.directories.len);

    // The commented example has to be valid once the `# ` is removed.
    var uncommented: std.ArrayList(u8) = .empty;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        const example = std.mem.startsWith(u8, line, "# directories:") or std.mem.startsWith(u8, line, "#   ");
        try uncommented.appendSlice(a, if (example) line[2..] else line);
        try uncommented.append(a, '\n');
    }
    const edited = try test_parse(a, uncommented.items, .linux, "/home/me");
    try std.testing.expectEqual(1, edited.directories.len);
    try std.testing.expectEqualStrings("/home/me/work/app", edited.directories[0].path);
    try std.testing.expectEqualStrings("192.168.1.20", edited.directories[0].server.address);
}

test "UserConfig load" {
    const io = std.testing.io;
    const dir = ".zig-cache/user_config_test";
    std.Io.Dir.cwd().deleteTree(io, dir) catch {};
    defer std.Io.Dir.cwd().deleteTree(io, dir) catch {};

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const base = try std.fs.path.join(a, &.{ try std.process.currentPathAlloc(io, a), dir });
    const path = try std.fs.path.join(a, &.{ base, "nested", file_name });

    var diag: config.Diagnostic = .{};
    try std.testing.expectError(error.FileNotFound, UserConfig.load(a, io, path, null, &diag));

    const real = try std.fs.path.join(a, &.{ base, "real" });
    const link = try std.fs.path.join(a, &.{ base, "link" });
    try std.Io.Dir.cwd().createDirPath(io, try std.fs.path.join(a, &.{ real, "src" }));
    // Not everyone may create symlinks on Windows, the rest still holds without one.
    const linked = if (std.Io.Dir.cwd().symLink(io, real, link, .{ .is_directory = true })) true else |_| false;

    const text = try std.fmt.allocPrint(a, "server:\n  address: 10.0.0.1\ndirectories:\n  '{s}':\n    address: 10.0.0.2\n", .{if (linked) link else real});
    try write_new(io, path, text);
    try std.testing.expectError(error.PathAlreadyExists, write_new(io, path, "server:\n"));

    const user = try UserConfig.load(a, io, path, null, &diag);
    try std.testing.expectEqualStrings("10.0.0.1", user.server.?.address);
    // We're in the repo root, which has no entry.
    try std.testing.expect(try user.find_here(a, io) == null);

    // Inside the directory, reached without going through the link.
    const inside = try std.Io.Dir.realPathFileAbsoluteAlloc(io, try std.fs.path.join(a, &.{ real, "src" }), a);
    try std.testing.expectEqualStrings("10.0.0.2", user.find(builtin.os.tag, &.{inside}).?.server.address);
}
