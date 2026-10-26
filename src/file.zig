const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const FileHandler = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    buffer: []u8,
    files: std.ArrayList([]const u8),
    hashed_files: std.StringHashMap(u256),

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, io: std.Io) Self {
        return .{
            .allocator = allocator,
            .io = io,
            .buffer = &.{},
            .files = .empty,
            .hashed_files = std.StringHashMap(u256).init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.buffer);
        self.hashed_files.deinit();
        self.files.deinit(self.allocator);
    }

    pub fn source_git_files(self: *Self) !void {
        const result = try std.process.run(self.allocator, self.io, .{
            .argv = &.{ "git", "ls-files" },
        });
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

        self.allocator.free(self.buffer);
        self.buffer = result.stdout;
        self.files.clearRetainingCapacity();
        self.hashed_files.clearRetainingCapacity();

        // "git ls-files" prints one repo-relative path per line.
        var lines = std.mem.tokenizeScalar(u8, self.buffer, '\n');
        while (lines.next()) |line| {
            try self.files.append(self.allocator, line);
        }
    }

    pub fn hash_files(self: *Self) !void {
        var file_buff: [128 * 1024]u8 = undefined;
        self.hashed_files.clearRetainingCapacity();

        for (self.get()) |file| {
            var hasher = Sha256.init(.{});
            const file_h = try std.Io.Dir.cwd().openFile(self.io, file, .{});
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

    pub fn get(self: *const Self) []const []const u8 {
        return self.files.items;
    }

    pub fn get_hashes(self: *const Self) std.StringHashMap(u256) {
        return self.hashed_files;
    }
};

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
            std.debug.print("{s} : {s}\n", .{ file.*, std.fmt.bytesToHex(buff, .lower) });
        }
    }
}
