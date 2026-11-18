const std = @import("std");
const builtin = @import("builtin");
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const FileHandler = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    /// Directory every path is relative to, and where git runs. Not owned.
    root: std.Io.Dir,
    buffer: []u8,
    files: std.ArrayList([]const u8),
    hashed_files: std.StringHashMap(u256),
    /// Names of files added with `create_file`. Git sourced names slice into `buffer`,
    /// these don't, so they are owned here.
    owned_names: std.ArrayList([]u8),

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, io: std.Io) Self {
        return init_in(allocator, io, std.Io.Dir.cwd());
    }

    /// Like `init` but rooted at `root` instead of the cwd. The caller keeps `root` open.
    pub fn init_in(allocator: std.mem.Allocator, io: std.Io, root: std.Io.Dir) Self {
        return .{
            .allocator = allocator,
            .io = io,
            .root = root,
            .buffer = &.{},
            .files = .empty,
            .hashed_files = std.StringHashMap(u256).init(allocator),
            .owned_names = .empty,
        };
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.buffer);
        self.hashed_files.deinit();
        self.files.deinit(self.allocator);
        self.free_owned_names();
        self.owned_names.deinit(self.allocator);
    }

    fn free_owned_names(self: *Self) void {
        for (self.owned_names.items) |name| self.allocator.free(name);
        self.owned_names.clearRetainingCapacity();
    }

    /// `root` as a working directory for child processes.
    pub fn child_cwd(self: *const Self) std.process.Child.Cwd {
        // The cwd handle is AT_FDCWD, which can't be fchdir'd to.
        return if (self.root.handle == std.Io.Dir.cwd().handle) .inherit else .{ .dir = self.root };
    }

    /// Reads `path` from `root`, caller frees.
    pub fn read_file(self: *const Self, allocator: std.mem.Allocator, path: []const u8) ![]u8 {
        // Payload lengths are u32 on the wire, leave headroom for the header and name.
        return self.root.readFileAlloc(self.io, path, allocator, .limited(std.math.maxInt(u32) - 64 * 1024));
    }

    /// Runs `argv` in `root`, returns stdout which the caller frees.
    fn git(self: *Self, argv: []const []const u8) ![]u8 {
        const result = try std.process.run(self.allocator, self.io, .{ .argv = argv, .cwd = self.child_cwd() });
        defer self.allocator.free(result.stderr);
        errdefer self.allocator.free(result.stdout);

        switch (result.term) {
            .exited => |code| if (code != 0) {
                std.debug.print("Command failed ({d}): {s}\n", .{ code, result.stderr });
                return error.CommandFailed;
            },
            else => {
                std.debug.print("Command exited abnormally: {any}\n", .{result.term});
                return error.CommandFailed;
            },
        }

        return result.stdout;
    }

    /// Sources the git tracked files. Only tracked files are synced, untracked ones
    /// (build output, caches, scratch files) never are, so new files need a `git add`.
    /// Tracked files deleted from disk without `git rm` are skipped, and so are submodules:
    /// git tracks one of those as a single entry, but on disk it's a directory.
    pub fn source_git_files(self: *Self) !void {
        // -z: NUL separated and unquoted, otherwise git escapes unusual paths.
        // -s: each entry is "<mode> <object> <stage>\t<path>", the mode tells submodules apart.
        const stdout = try self.git(&.{ "git", "ls-files", "-z", "-s" });

        self.allocator.free(self.buffer);
        self.buffer = stdout;
        self.files.clearRetainingCapacity();
        self.hashed_files.clearRetainingCapacity();
        self.free_owned_names();

        var entries = std.mem.tokenizeScalar(u8, self.buffer, 0);
        var previous: []const u8 = "";
        while (entries.next()) |entry| {
            const tab = std.mem.indexOfScalar(u8, entry, '\t') orelse return error.UnexpectedGitOutput;
            if (std.mem.startsWith(u8, entry, "160000 ")) continue;
            const path = entry[tab + 1 ..];
            // A path with a merge conflict is listed once per stage.
            if (std.mem.eql(u8, path, previous)) continue;
            previous = path;

            self.root.access(self.io, path, .{}) catch |err| switch (err) {
                error.FileNotFound => continue,
                else => return err,
            };
            try self.files.append(self.allocator, path);
        }
    }

    pub fn hash_files(self: *Self) !void {
        var file_buff: [128 * 1024]u8 = undefined;
        self.hashed_files.clearRetainingCapacity();

        for (self.get()) |file| {
            var hasher = Sha256.init(.{});
            const file_h = try self.root.openFile(self.io, file, .{});
            defer file_h.close(self.io);

            read_file: while (true) {
                const n = file_h.readStreaming(self.io, &.{&file_buff}) catch |err| switch (err) {
                    error.EndOfStream => break :read_file,
                    else => return err,
                };
                hasher.update(file_buff[0..n]);
            }

            const hash = hasher.finalResult();
            const hash_le = std.mem.readInt(u256, &hash, .little);
            try self.hashed_files.put(file, hash_le);
        }
    }

    /// Overwrites the tracked file `path`. `hash` must be its current hash, so a file
    /// that changed since the client last saw it is never clobbered.
    pub fn replace_file(self: *Self, path: []const u8, hash: u256, data: []const u8) !u256 {
        try validate_path(path);
        const current = self.hashed_files.getPtr(path) orelse return error.FileNotTracked;
        if (current.* != hash) return error.StaleHash;

        try self.root.writeFile(self.io, .{ .sub_path = path, .data = data });

        var new_hash: [32]u8 = undefined;
        Sha256.hash(data, &new_hash, .{});
        current.* = std.mem.readInt(u256, &new_hash, .little);

        return current.*;
    }

    /// Creates a new file at `path`, making parent directories as needed, and `git add`s it so
    /// it stays tracked. Fails if the file is already tracked or already on disk.
    pub fn create_file(self: *Self, path: []const u8, data: []const u8) !u256 {
        try validate_path(path);
        if (self.hashed_files.contains(path)) return error.FileExists;

        // Reserve everything up front so nothing can fail after the file is on disk.
        try self.owned_names.ensureUnusedCapacity(self.allocator, 1);
        try self.files.ensureUnusedCapacity(self.allocator, 1);
        try self.hashed_files.ensureUnusedCapacity(1);

        const name = try self.allocator.dupe(u8, path);
        errdefer self.allocator.free(name);

        if (std.fs.path.dirnamePosix(path)) |dir| try self.root.createDirPath(self.io, dir);
        try self.root.writeFile(self.io, .{ .sub_path = path, .data = data, .flags = .{ .exclusive = true } });
        errdefer self.root.deleteFile(self.io, path) catch {};

        // -f: the client tracks this file, so track it even if the server's .gitignore matches it.
        self.allocator.free(try self.git(&.{ "git", "add", "-f", "--", path }));

        var hash: [32]u8 = undefined;
        Sha256.hash(data, &hash, .{});
        const hash_le = std.mem.readInt(u256, &hash, .little);

        self.owned_names.appendAssumeCapacity(name);
        self.files.appendAssumeCapacity(name);
        self.hashed_files.putAssumeCapacityNoClobber(name, hash_le);

        return hash_le;
    }

    /// `git rm`s the tracked file `path`. `hash` must be its current hash, same as `replace_file`.
    pub fn delete_file(self: *Self, path: []const u8, hash: u256) !void {
        try validate_path(path);
        const current = self.hashed_files.get(path) orelse return error.FileNotTracked;
        if (current != hash) return error.StaleHash;

        // -f: the hash check above already proved this is the version the client meant to delete,
        // git would otherwise refuse files with unstaged changes (e.g. after a replace).
        self.allocator.free(try self.git(&.{ "git", "rm", "-f", "-q", "--", path }));

        _ = self.hashed_files.remove(path);
        for (self.files.items, 0..) |file, i| {
            if (std.mem.eql(u8, file, path)) {
                _ = self.files.swapRemove(i);
                break;
            }
        }
    }

    /// `path` comes off the network, reject anything that could land outside `root` or inside a
    /// `.git` directory (a synced hook would run on the server). Git refuses to track `.git`
    /// paths too, so a real repo never needs one.
    fn validate_path(path: []const u8) !void {
        return validate_path_for(builtin.os.tag, path);
    }

    pub fn get(self: *const Self) []const []const u8 {
        return self.files.items;
    }

    pub fn get_hashes(self: *const Self) std.StringHashMap(u256) {
        return self.hashed_files;
    }
};

/// Throwaway git repo for tests, so `git add`/`git rm` never touch the real repo's index.
pub const TestRepo = struct {
    io: std.Io,
    path: []const u8,
    dir: std.Io.Dir,

    pub fn init(io: std.Io, path: []const u8) !TestRepo {
        const cwd = std.Io.Dir.cwd();
        cwd.deleteTree(io, path) catch {};
        try cwd.createDirPath(io, path);
        const dir = try cwd.openDir(io, path, .{});
        errdefer dir.close(io);

        var handler = FileHandler.init_in(std.testing.allocator, io, dir);
        defer handler.deinit();
        std.testing.allocator.free(try handler.git(&.{ "git", "init", "-q" }));

        return .{ .io = io, .path = path, .dir = dir };
    }

    pub fn deinit(self: *TestRepo) void {
        self.dir.close(self.io);
        std.Io.Dir.cwd().deleteTree(self.io, self.path) catch {};
    }
};

fn sha(data: []const u8) u256 {
    var hash: [32]u8 = undefined;
    Sha256.hash(data, &hash, .{});
    return std.mem.readInt(u256, &hash, .little);
}

test "Get Files" {
    var handler: FileHandler = FileHandler.init(std.testing.allocator, std.testing.io);
    defer handler.deinit();
    try handler.source_git_files();

    try std.testing.expect(handler.get().len > 0);
}

test "Get Hashes" {
    var handler: FileHandler = FileHandler.init(std.testing.allocator, std.testing.io);
    defer handler.deinit();
    try handler.source_git_files();
    try std.testing.expect(handler.get().len > 0);

    try handler.hash_files();
    try std.testing.expect(handler.get_hashes().count() > 0);

    const test_hash = handler.get_hashes().get("test.txt");
    try std.testing.expect(test_hash != null);

    var test_hash_buff: [32]u8 = undefined;

    // sha256 hash of test.txt
    _ = try std.fmt.hexToBytes(&test_hash_buff, "f91955996a18fc351e9a5d020bb1806196db8160840302d94ac847b86b27c3d1");

    const int = std.mem.readInt(u256, &test_hash_buff, .little);
    try std.testing.expect(test_hash.? == int);

    var it = handler.get_hashes().keyIterator();
    while (it.next()) |file| {
        const hash_ = handler.get_hashes().get(file.*);
        if (hash_) |hash| {
            var buff: [32]u8 = undefined;
            std.mem.writeInt(u256, &buff, hash, .little);
            std.log.debug("{s} : {s}", .{ file.*, std.fmt.bytesToHex(buff, .lower) });
        }
    }
}

test "Replace File" {
    const io = std.testing.io;
    var repo = try TestRepo.init(io, ".zig-cache/replace_test");
    defer repo.deinit();

    var handler: FileHandler = .init_in(std.testing.allocator, io, repo.dir);
    defer handler.deinit();

    // Two files with the same contents, only the named one may change.
    _ = try handler.create_file("a.txt", "old");
    _ = try handler.create_file("b.txt", "old");

    const new_hash = try handler.replace_file("a.txt", sha("old"), "new");
    try std.testing.expect(new_hash == sha("new"));
    try std.testing.expect(handler.get_hashes().get("a.txt").? == new_hash);
    try std.testing.expect(handler.get_hashes().get("b.txt").? == sha("old"));

    var buff: [16]u8 = undefined;
    try std.testing.expectEqualStrings("new", try repo.dir.readFile(io, "a.txt", &buff));
    try std.testing.expectEqualStrings("old", try repo.dir.readFile(io, "b.txt", &buff));

    // The client's view of a.txt is out of date.
    try std.testing.expectError(error.StaleHash, handler.replace_file("a.txt", sha("old"), "x"));
    try std.testing.expectError(error.FileNotTracked, handler.replace_file("nope.txt", 0, "x"));
    try std.testing.expectError(error.InvalidPath, handler.replace_file("../a.txt", 0, "x"));
}

test "Submodules are skipped" {
    const io = std.testing.io;
    var repo = try TestRepo.init(io, ".zig-cache/submodule_test");
    defer repo.deinit();

    var handler: FileHandler = .init_in(std.testing.allocator, io, repo.dir);
    defer handler.deinit();

    try repo.dir.writeFile(io, .{ .sub_path = "a.txt", .data = "a" });
    try repo.dir.createDirPath(io, "sub");
    std.testing.allocator.free(try handler.git(&.{ "git", "add", "a.txt" }));
    // A gitlink, which is what a submodule is in the index, without cloning one.
    std.testing.allocator.free(try handler.git(&.{ "git", "update-index", "--add", "--cacheinfo", "160000,84bf53e4a3d0bfe3f60db15edf3861d2abd446b6,sub" }));

    try handler.source_git_files();
    try handler.hash_files();
    try std.testing.expectEqual(@as(usize, 1), handler.get().len);
    try std.testing.expectEqualStrings("a.txt", handler.get()[0]);
}

test "Create File" {
    const io = std.testing.io;
    var repo = try TestRepo.init(io, ".zig-cache/create_test");
    defer repo.deinit();

    var handler: FileHandler = .init_in(std.testing.allocator, io, repo.dir);
    defer handler.deinit();

    const path = "sub/new.txt";
    const hash = try handler.create_file(path, "hello");

    try std.testing.expect(hash == sha("hello"));
    try std.testing.expect(handler.get_hashes().get(path).? == hash);
    try std.testing.expectEqualStrings(path, handler.get()[handler.get().len - 1]);

    var buff: [16]u8 = undefined;
    try std.testing.expectEqualStrings("hello", try repo.dir.readFile(io, path, &buff));

    // Staged, so it's still known after re-sourcing.
    try handler.source_git_files();
    try handler.hash_files();
    try std.testing.expect(handler.get_hashes().get(path).? == hash);

    // Already tracked.
    try std.testing.expectError(error.FileExists, handler.create_file(path, "again"));

    // Not tracked by this handler, but already on disk.
    var other: FileHandler = .init_in(std.testing.allocator, io, repo.dir);
    defer other.deinit();
    try std.testing.expectError(error.PathAlreadyExists, other.create_file(path, "again"));
    try std.testing.expect(other.get_hashes().count() == 0);

    // Paths that escape the root.
    try std.testing.expectError(error.InvalidPath, handler.create_file("../escape.txt", "x"));
    try std.testing.expectError(error.InvalidPath, handler.create_file("sub/../../escape.txt", "x"));
    try std.testing.expectError(error.InvalidPath, handler.create_file("/tmp/escape.txt", "x"));
    try std.testing.expectError(error.InvalidPath, handler.create_file("", "x"));
}

test "Delete File" {
    const io = std.testing.io;
    var repo = try TestRepo.init(io, ".zig-cache/delete_test");
    defer repo.deinit();

    var handler: FileHandler = .init_in(std.testing.allocator, io, repo.dir);
    defer handler.deinit();

    _ = try handler.create_file("keep.txt", "same");
    _ = try handler.create_file("sub/gone.txt", "same");
    _ = try handler.replace_file("sub/gone.txt", sha("same"), "changed");

    // Out of date view of the file, nothing happens.
    try std.testing.expectError(error.StaleHash, handler.delete_file("sub/gone.txt", sha("same")));
    try repo.dir.access(io, "sub/gone.txt", .{});

    // Has unstaged changes from the replace, still deletes.
    try handler.delete_file("sub/gone.txt", sha("changed"));
    try std.testing.expectError(error.FileNotFound, repo.dir.access(io, "sub/gone.txt", .{}));
    try std.testing.expect(handler.get_hashes().get("sub/gone.txt") == null);
    try std.testing.expect(handler.get().len == 1);

    // Gone from git too.
    try handler.source_git_files();
    try std.testing.expect(handler.get().len == 1);
    try std.testing.expectEqualStrings("keep.txt", handler.get()[0]);

    try std.testing.expectError(error.FileNotTracked, handler.delete_file("sub/gone.txt", sha("changed")));
}

test "Source skips files deleted from disk" {
    const io = std.testing.io;
    var repo = try TestRepo.init(io, ".zig-cache/source_deleted_test");
    defer repo.deinit();

    var handler: FileHandler = .init_in(std.testing.allocator, io, repo.dir);
    defer handler.deinit();

    _ = try handler.create_file("a.txt", "a");
    _ = try handler.create_file("b.txt", "b");

    // Plain rm, git still lists it.
    try repo.dir.deleteFile(io, "a.txt");

    try handler.source_git_files();
    try handler.hash_files();
    try std.testing.expect(handler.get().len == 1);
    try std.testing.expect(handler.get_hashes().get("b.txt").? == sha("b"));
}

fn validate_path_for(os: std.Target.Os.Tag, path: []const u8) !void {
    if (path.len == 0) return error.InvalidPath;
    if (std.mem.indexOfScalar(u8, path, 0) != null) return error.InvalidPath;
    const absolute = if (os == .windows) std.fs.path.isAbsoluteWindows(path) else std.fs.path.isAbsolutePosix(path);
    if (absolute) return error.InvalidPath;

    var parts = std.mem.tokenizeAny(u8, path, "/\\");
    while (parts.next()) |part| {
        if (std.mem.eql(u8, part, "..")) return error.InvalidPath;
        if (std.ascii.eqlIgnoreCase(part, ".git")) return error.InvalidPath;
        if (os == .windows) try validate_windows_part(part);
    }
}

/// Windows quietly reinterprets some names, so they could alias or escape the intended file.
fn validate_windows_part(part: []const u8) !void {
    // "C:foo" is relative to drive C's cwd, "file:stream" is an alternate data stream.
    for (part) |c| {
        if (c < 0x20 or std.mem.indexOfScalar(u8, "<>:\"|?*", c) != null) return error.InvalidPath;
    }
    // Trailing dots and spaces are stripped, so ".git." is ".git" and "a." is "a".
    if (part[part.len - 1] == '.' or part[part.len - 1] == ' ') return error.InvalidPath;
    // The 8.3 short name of .git.
    if (std.ascii.eqlIgnoreCase(part, "git~1")) return error.InvalidPath;

    // Device names open the device instead of a file, with any extension: "nul.txt" is NUL.
    const stem = std.mem.trimEnd(u8, part[0 .. std.mem.indexOfScalar(u8, part, '.') orelse part.len], " ");
    const devices = [_][]const u8{ "con", "prn", "aux", "nul", "conin$", "conout$" };
    for (devices) |device| {
        if (std.ascii.eqlIgnoreCase(stem, device)) return error.InvalidPath;
    }
    if (stem.len == 4 and (std.ascii.startsWithIgnoreCase(stem, "com") or std.ascii.startsWithIgnoreCase(stem, "lpt")) and
        stem[3] >= '0' and stem[3] <= '9') return error.InvalidPath;
}

test "Path validation" {
    const ok = [_][]const u8{ "a.txt", "src/main.zig", "sub\\dir\\file.cs", ".gitignore", ".github/workflows/ci.yml", "dir.d/x", "console.log", "com10.txt" };
    for (ok) |path| {
        try validate_path_for(.linux, path);
        try validate_path_for(.windows, path);
    }

    const bad_everywhere = [_][]const u8{ "", "../x", "a/../../x", "/etc/passwd", ".git/hooks/pre-commit", "sub/.GIT/config", "a\\..\\..\\x" };
    for (bad_everywhere) |path| {
        try std.testing.expectError(error.InvalidPath, validate_path_for(.linux, path));
        try std.testing.expectError(error.InvalidPath, validate_path_for(.windows, path));
    }

    // Fine as names on Linux, but special on Windows.
    const bad_on_windows = [_][]const u8{
        "C:\\Windows\\x", "C:foo",       "\\\\server\\share\\x", "file.txt:stream",
        ".git.",          "GIT~1/hooks", "nul",                  "NUL.txt",
        "src/con",        "aux .txt",    "COM1",                 "lpt9.log",
        "trailing.",      "space ",      "what?.txt",
    };
    for (bad_on_windows) |path| {
        try std.testing.expectError(error.InvalidPath, validate_path_for(.windows, path));
    }
    try validate_path_for(.linux, "file.txt:stream");
    try validate_path_for(.linux, "nul");
}
