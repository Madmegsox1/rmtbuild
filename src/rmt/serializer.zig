const std = @import("std");

pub const Bytes = struct {
    bytes: []u8,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, bytes: []u8) Bytes {
        return .{
            .bytes = bytes,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *const Bytes) void {
        self.allocator.free(self.bytes);
    }
};

pub fn string_map_to_bytes(comptime T: type, allocator: std.mem.Allocator, map: std.StringHashMap(T)) !Bytes {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(allocator);

    var it = map.iterator();

    while (it.next()) |entry| {
        const key = entry.key_ptr.*;
        var len_buff: [4]u8 = undefined;
        std.mem.writeInt(u32, &len_buff, @intCast(key.len), .little);
        try list.appendSlice(allocator, &len_buff);

        try list.appendSlice(allocator, key);

        var hash_buf: [@sizeOf(T)]u8 = undefined;
        std.mem.writeInt(T, &hash_buf, entry.value_ptr.*, .little);
        try list.appendSlice(allocator, &hash_buf);
    }

    return .init(allocator, try list.toOwnedSlice(allocator));
}

pub fn bytes_to_string_map(comptime T: type, allocator: std.mem.Allocator, bytes: []const u8) !std.StringHashMap(T) {
    var map = std.StringHashMap(T).init(allocator);
    errdefer map.deinit();

    var i: usize = 0;

    while (i < bytes.len) {
        if (bytes.len - i < 4) return error.Trucated;

        const len = std.mem.readInt(u32, bytes[i..][0..4], .little);
        i += 4;
        if (bytes.len - i < len + @sizeOf(T)) return error.Trucated;
        const key = bytes[i .. i + len];
        i += len;
        const value = std.mem.readInt(T, bytes[i..][0..@sizeOf(T)], .little);
        i += @sizeOf(T);

        try map.put(key, value);
    }

    return map;
}

pub fn string_list_to_bytes(allocator: std.mem.Allocator, list_in: []const []const u8) !Bytes {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(allocator);

    for (list_in) |str| {
        var len_buff: [4]u8 = undefined;
        std.mem.writeInt(u32, &len_buff, @intCast(str.len), .little);
        try list.appendSlice(allocator, &len_buff);

        try list.appendSlice(allocator, str);
    }

    return .init(allocator, try list.toOwnedSlice(allocator));
}

/// Returned strings are slices into `bytes`, free the list with `allocator`.
pub fn bytes_to_string_list(allocator: std.mem.Allocator, bytes: []const u8) !std.ArrayList([]const u8) {
    var list: std.ArrayList([]const u8) = .empty;
    errdefer list.deinit(allocator);

    var i: usize = 0;

    while (i < bytes.len) {
        if (bytes.len - i < 4) return error.Trucated;

        const len = std.mem.readInt(u32, bytes[i..][0..4], .little);
        i += 4;
        if (bytes.len - i < len) return error.Trucated;
        try list.append(allocator, bytes[i .. i + len]);
        i += len;
    }

    return list;
}

/// RMT_FN payload layout: `[u32 name_len][name][data]`.
/// Only the name is length prefixed, `data` runs to the end of the payload. The payload's
/// total length is already known from the packet's `transfer_len`, so the data length is
/// whatever is left after the name.
pub const FilePayload = struct {
    name: []const u8,
    data: []const u8,
};

pub fn file_payload_to_bytes(allocator: std.mem.Allocator, name: []const u8, data: []const u8) !Bytes {
    const name_len = std.math.cast(u32, name.len) orelse return error.NameTooLong;

    const buf = try allocator.alloc(u8, 4 + name.len + data.len);
    std.mem.writeInt(u32, buf[0..4], name_len, .little);
    @memcpy(buf[4..][0..name.len], name);
    @memcpy(buf[4 + name.len ..], data);

    return .init(allocator, buf);
}

/// Returned slices point into `bytes`.
pub fn bytes_to_file_payload(bytes: []const u8) !FilePayload {
    if (bytes.len < 4) return error.Trucated;

    const len = std.mem.readInt(u32, bytes[0..4], .little);
    if (bytes.len - 4 < len) return error.Trucated;

    return .{
        .name = bytes[4..][0..len],
        .data = bytes[4 + len ..],
    };
}

test "File Payload Serialization" {
    const bytes = try file_payload_to_bytes(std.testing.allocator, "src/new.zig", "const x = 1;\n");
    defer bytes.deinit();

    const payload = try bytes_to_file_payload(bytes.bytes);
    try std.testing.expectEqualStrings("src/new.zig", payload.name);
    try std.testing.expectEqualStrings("const x = 1;\n", payload.data);

    // Empty files are valid, the payload is just the name.
    const empty = try file_payload_to_bytes(std.testing.allocator, "empty.txt", "");
    defer empty.deinit();
    const empty_payload = try bytes_to_file_payload(empty.bytes);
    try std.testing.expectEqualStrings("empty.txt", empty_payload.name);
    try std.testing.expect(empty_payload.data.len == 0);

    // Name length claims more bytes than were sent.
    try std.testing.expectError(error.Trucated, bytes_to_file_payload(bytes.bytes[0..6]));
    try std.testing.expectError(error.Trucated, bytes_to_file_payload(bytes.bytes[0..2]));
}

test "List Serialization" {
    const strs: []const []const u8 = &.{ "a.txt", "", "src/b.zig" };

    const bytes = try string_list_to_bytes(std.testing.allocator, strs);
    defer bytes.deinit();

    var list_back = try bytes_to_string_list(std.testing.allocator, bytes.bytes);
    defer list_back.deinit(std.testing.allocator);

    try std.testing.expect(list_back.items.len == strs.len);
    for (strs, list_back.items) |a, b| {
        try std.testing.expectEqualStrings(a, b);
    }
}

test "Hash Serialization" {
    var map: std.StringHashMap(u32) = .init(std.testing.allocator);
    defer map.deinit();
    try map.put("Test", 1010);
    try map.put("Test2", 1111);
    try map.put("Test3", 0);

    try std.testing.expect(@sizeOf(u32) == 4);

    const bytes = try string_map_to_bytes(u32, std.testing.allocator, map);
    defer bytes.deinit();

    var map_back: std.StringHashMap(u32) = try bytes_to_string_map(u32, std.testing.allocator, bytes.bytes);
    defer map_back.deinit();

    try std.testing.expect(map.get("Test").? == map_back.get("Test").?);
    try std.testing.expect(map.get("Test2").? == map_back.get("Test2").?);
    try std.testing.expect(map.get("Test3").? == map_back.get("Test3").?);
}
