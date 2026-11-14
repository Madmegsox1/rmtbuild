//! Shared key authentication, run at the start of every connection before any packet:
//!
//!   server -> client: nonce_s
//!   client -> server: nonce_c ‖ HMAC(key, "rmtbuild client" ‖ nonce_s ‖ nonce_c)
//!   server -> client: HMAC(key, "rmtbuild server" ‖ nonce_c ‖ nonce_s)
//!
//! Both sides prove they hold the key without sending it, and fresh nonces on each side stop a
//! recorded handshake being replayed. The server checks the client before reading any packet,
//! so an unauthenticated peer can't make it allocate anything. Nothing is encrypted, that's
//! left to the VPN.
const std = @import("std");
const builtin = @import("builtin");
const net = std.Io.net;
const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;

pub const key_len = 32;
pub const Key = [key_len]u8;
const Nonce = [32]u8;
const Mac = [Hmac.mac_length]u8;

/// Hex key, overrides the key file when set.
pub const key_env = "RMTBUILD_KEY";

const client_label = "rmtbuild client";
const server_label = "rmtbuild server";

fn mac(key: *const Key, label: []const u8, first: *const Nonce, second: *const Nonce) Mac {
    var out: Mac = undefined;
    var h = Hmac.init(key);
    h.update(label);
    h.update(first);
    h.update(second);
    h.final(&out);
    return out;
}

/// The reader's buffer is exactly `n` bytes, so it can never read past the handshake into the
/// packets that follow (those are read with the caller's own reader).
fn read_exact(io: std.Io, stream: net.Stream, comptime n: usize) ![n]u8 {
    var buf: [n]u8 = undefined;
    var reader = stream.reader(io, &buf);
    return (try reader.interface.takeArray(n)).*;
}

fn write_all(io: std.Io, stream: net.Stream, bytes: []const u8) !void {
    var buf: [64]u8 = undefined;
    var writer = stream.writer(io, &buf);
    try writer.interface.writeAll(bytes);
    try writer.interface.flush();
}

pub fn client_handshake(io: std.Io, key: *const Key, stream: net.Stream) !void {
    const nonce_s = read_exact(io, stream, @sizeOf(Nonce)) catch |err| switch (err) {
        error.EndOfStream => return error.ConnectionClosed,
        else => return err,
    };

    var nonce_c: Nonce = undefined;
    try io.randomSecure(&nonce_c);

    var msg: [@sizeOf(Nonce) + @sizeOf(Mac)]u8 = undefined;
    msg[0..@sizeOf(Nonce)].* = nonce_c;
    msg[@sizeOf(Nonce)..].* = mac(key, client_label, &nonce_s, &nonce_c);
    try write_all(io, stream, &msg);

    // The server hangs up instead of answering when our proof is wrong.
    const server_mac = read_exact(io, stream, @sizeOf(Mac)) catch |err| switch (err) {
        error.EndOfStream => return error.AuthRejected,
        else => return err,
    };
    const expected = mac(key, server_label, &nonce_c, &nonce_s);
    if (!std.crypto.timing_safe.eql(Mac, server_mac, expected)) return error.ServerAuthFailed;
}

pub fn server_handshake(io: std.Io, key: *const Key, stream: net.Stream) !void {
    var nonce_s: Nonce = undefined;
    try io.randomSecure(&nonce_s);
    try write_all(io, stream, &nonce_s);

    const msg = try read_exact(io, stream, @sizeOf(Nonce) + @sizeOf(Mac));
    const nonce_c: Nonce = msg[0..@sizeOf(Nonce)].*;
    const client_mac: Mac = msg[@sizeOf(Nonce)..].*;

    const expected = mac(key, client_label, &nonce_s, &nonce_c);
    if (!std.crypto.timing_safe.eql(Mac, client_mac, expected)) return error.AuthFailed;

    try write_all(io, stream, &mac(key, server_label, &nonce_c, &nonce_s));
}

pub fn generate_key(io: std.Io) !Key {
    var key: Key = undefined;
    try io.randomSecure(&key);
    return key;
}

pub fn parse_key(text: []const u8) !Key {
    const hex = std.mem.trim(u8, text, " \t\r\n");
    if (hex.len != key_len * 2) return error.InvalidKey;
    var key: Key = undefined;
    _ = std.fmt.hexToBytes(&key, hex) catch return error.InvalidKey;
    return key;
}

/// Unix permission bits. On Windows the key relies on %APPDATA% being private to the user,
/// which it is by default.
const has_mode = @hasDecl(std.Io.File.Permissions, "toMode");

/// `$XDG_CONFIG_HOME/rmtbuild/key`, otherwise `%APPDATA%\rmtbuild\key` on Windows and
/// `~/.config/rmtbuild/key` elsewhere. Caller frees.
pub fn default_key_path(allocator: std.mem.Allocator, environ: *const std.process.Environ.Map) ![]u8 {
    return default_key_path_for(builtin.os.tag, allocator, environ);
}

fn default_key_path_for(os: std.Target.Os.Tag, allocator: std.mem.Allocator, environ: *const std.process.Environ.Map) ![]u8 {
    if (nonempty(environ.get("XDG_CONFIG_HOME"))) |dir| return join(os, allocator, &.{ dir, "rmtbuild", "key" });
    if (os == .windows) {
        const appdata = nonempty(environ.get("APPDATA")) orelse return error.NoHomeDir;
        return join(os, allocator, &.{ appdata, "rmtbuild", "key" });
    }
    const home = nonempty(environ.get("HOME")) orelse return error.NoHomeDir;
    return join(os, allocator, &.{ home, ".config", "rmtbuild", "key" });
}

fn nonempty(value: ?[]const u8) ?[]const u8 {
    const v = value orelse return null;
    return if (v.len == 0) null else v;
}

fn join(os: std.Target.Os.Tag, allocator: std.mem.Allocator, parts: []const []const u8) ![]u8 {
    return std.mem.join(allocator, if (os == .windows) "\\" else "/", parts);
}

pub const LoadKeyError = error{ KeyFileTooOpen, InvalidKey, InvalidKeyEnv } ||
    std.Io.File.OpenError || std.Io.File.StatError || std.Io.File.ReadPositionalError;

/// `RMTBUILD_KEY` if set, otherwise the key file at `path`.
pub fn load_key(io: std.Io, environ: *const std.process.Environ.Map, path: []const u8) LoadKeyError!Key {
    if (environ.get(key_env)) |hex| return parse_key(hex) catch error.InvalidKeyEnv;

    const file = try std.Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);

    // Same rule as ssh: a key others can read isn't secret.
    if (has_mode) {
        const stat = try file.stat(io);
        if (stat.permissions.toMode() & 0o077 != 0) return error.KeyFileTooOpen;
    }

    // Room for the hex key plus trailing whitespace, anything longer fails to parse.
    var buf: [key_len * 2 + 16]u8 = undefined;
    const n = try file.readPositionalAll(io, &buf, 0);
    return parse_key(buf[0..n]);
}

/// Writes `key` to `path` readable only by the owner, making parent directories as needed.
pub fn write_key_file(io: std.Io, path: []const u8, key: Key, overwrite: bool) !void {
    const cwd = std.Io.Dir.cwd();
    if (std.fs.path.dirname(path)) |dir| try cwd.createDirPath(io, dir);
    // Delete first so the new file is created with 0600, truncating keeps the old permissions.
    if (overwrite) cwd.deleteFile(io, path) catch |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    };

    var text: [key_len * 2 + 1]u8 = undefined;
    text[0 .. key_len * 2].* = std.fmt.bytesToHex(key, .lower);
    text[key_len * 2] = '\n';

    try cwd.writeFile(io, .{
        .sub_path = path,
        .data = &text,
        .flags = .{ .exclusive = true, .permissions = if (has_mode) .fromMode(0o600) else .default_file },
    });
}

const HandshakeResult = struct { server: ?anyerror = null, client: ?anyerror = null };

fn serverSide(listen: *net.Server, key: *const Key, err_out: *?anyerror) void {
    const stream = listen.accept(std.testing.io) catch |err| {
        err_out.* = err;
        return;
    };
    defer stream.close(std.testing.io);
    server_handshake(std.testing.io, key, stream) catch |err| {
        err_out.* = err;
    };
}

fn try_handshake(port: u16, server_key: Key, client_key: Key) !HandshakeResult {
    const io = std.testing.io;
    const addr = try net.IpAddress.parse("127.0.0.1", port);
    var listen = try addr.listen(io, .{ .mode = .stream, .protocol = .tcp, .reuse_address = true });
    defer listen.deinit(io);

    var result: HandshakeResult = .{};
    const thread = try std.Thread.spawn(.{}, serverSide, .{ &listen, &server_key, &result.server });

    const stream = try addr.connect(io, .{ .mode = .stream });
    client_handshake(io, &client_key, stream) catch |err| {
        result.client = err;
    };
    stream.close(io);
    thread.join();
    return result;
}

test "Handshake" {
    const key = try generate_key(std.testing.io);
    var other = key;
    other[0] ^= 1;

    const ok = try try_handshake(8110, key, key);
    try std.testing.expectEqual(HandshakeResult{}, ok);

    // Client has the wrong key: server hangs up without proving itself.
    const bad_client = try try_handshake(8111, key, other);
    try std.testing.expectEqual(error.AuthFailed, bad_client.server.?);
    try std.testing.expectEqual(error.AuthRejected, bad_client.client.?);

    // Server has the wrong key: client refuses it before sending anything else.
    const bad_server = try try_handshake(8112, other, key);
    try std.testing.expectEqual(error.AuthFailed, bad_server.server.?);
    try std.testing.expectEqual(error.AuthRejected, bad_server.client.?);
}

test "Handshake proofs" {
    const key = [_]u8{7} ** key_len;
    const a = [_]u8{1} ** 32;
    const b = [_]u8{2} ** 32;

    // Reflecting the server's proof back as the client's must not work.
    try std.testing.expect(!std.mem.eql(u8, &mac(&key, client_label, &a, &b), &mac(&key, server_label, &a, &b)));
    // Nonce order matters, so swapping them doesn't replay a proof either.
    try std.testing.expect(!std.mem.eql(u8, &mac(&key, client_label, &a, &b), &mac(&key, client_label, &b, &a)));
}

test "Key parsing" {
    const key = try generate_key(std.testing.io);
    const hex = std.fmt.bytesToHex(key, .lower);

    try std.testing.expectEqual(key, try parse_key(&hex));
    try std.testing.expectEqual(key, try parse_key(" " ++ hex ++ "\n"));
    try std.testing.expectError(error.InvalidKey, parse_key(hex[1..]));
    try std.testing.expectError(error.InvalidKey, parse_key("zz" ++ hex[2..]));
}

test "Key file" {
    const io = std.testing.io;
    const dir = ".zig-cache/key_test";
    const path = dir ++ "/nested/key";
    std.Io.Dir.cwd().deleteTree(io, dir) catch {};
    defer std.Io.Dir.cwd().deleteTree(io, dir) catch {};

    var environ: std.process.Environ.Map = .init(std.testing.allocator);
    defer environ.deinit();

    const key = try generate_key(io);
    try write_key_file(io, path, key, false);
    try std.testing.expectEqual(key, try load_key(io, &environ, path));

    // Won't clobber an existing key unless asked.
    const new_key = try generate_key(io);
    try std.testing.expectError(error.PathAlreadyExists, write_key_file(io, path, new_key, false));
    try write_key_file(io, path, new_key, true);
    try std.testing.expectEqual(new_key, try load_key(io, &environ, path));

    // The env var wins over the file.
    const env_hex = std.fmt.bytesToHex(key, .lower);
    try environ.put(key_env, &env_hex);
    try std.testing.expectEqual(key, try load_key(io, &environ, path));
    try environ.put(key_env, "nope");
    try std.testing.expectError(error.InvalidKeyEnv, load_key(io, &environ, path));
    _ = environ.swapRemove(key_env);

    // Readable by others: refused.
    if (has_mode) {
        const open_path = dir ++ "/open_key";
        try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = open_path, .data = &env_hex, .flags = .{ .permissions = .fromMode(0o644) } });
        try std.testing.expectError(error.KeyFileTooOpen, load_key(io, &environ, open_path));
    }
}

test "Default key path" {
    var environ: std.process.Environ.Map = .init(std.testing.allocator);
    defer environ.deinit();

    const a = std.testing.allocator;
    try std.testing.expectError(error.NoHomeDir, default_key_path_for(.linux, a, &environ));
    try std.testing.expectError(error.NoHomeDir, default_key_path_for(.windows, a, &environ));

    try environ.put("HOME", "/home/me");
    try environ.put("APPDATA", "C:\\Users\\me\\AppData\\Roaming");

    const home_path = try default_key_path_for(.linux, a, &environ);
    defer a.free(home_path);
    try std.testing.expectEqualStrings("/home/me/.config/rmtbuild/key", home_path);

    const appdata_path = try default_key_path_for(.windows, a, &environ);
    defer a.free(appdata_path);
    try std.testing.expectEqualStrings("C:\\Users\\me\\AppData\\Roaming\\rmtbuild\\key", appdata_path);

    try environ.put("XDG_CONFIG_HOME", "/cfg");
    const xdg_path = try default_key_path_for(.linux, a, &environ);
    defer a.free(xdg_path);
    try std.testing.expectEqualStrings("/cfg/rmtbuild/key", xdg_path);
}
