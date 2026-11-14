//! `rmtbuild.yaml`, read with a small YAML subset parser:
//! nested `key: value` maps by indentation, `#` comments, '...' and "..." quoted scalars,
//! and `|` / `|-` literal blocks for multi-line values.
//! Not supported (and reported as errors): lists, flow style `{}`/`[]`, anchors, tags,
//! tabs for indentation, multiple documents.
//!
//! ```yaml
//! server:
//!   address: 192.168.1.20  # where the client connects
//!   port: 8099
//!   listen: 0.0.0.0        # where `rmtbuild serve` binds, default 127.0.0.1
//!   max_payload_mb: 256    # largest file the server accepts, default 256
//! commands:
//!   build:
//!     run: zig build
//!   test:
//!     run: |
//!       zig build test
//!       echo done
//!   web:
//!     run: zig build run
//!     forward: 8080        # or "8080, 3000", or "8081:8080" for local:remote
//! ```
const std = @import("std");
const Allocator = std.mem.Allocator;

pub const file_name = "rmtbuild.yaml";

/// Names that are CLI subcommands, so can't be used for commands.
pub const reserved_names = [_][]const u8{ "serve", "keygen", "help" };

pub const Diagnostic = struct {
    /// 1 based, 0 when the problem isn't tied to a line.
    line: usize = 0,
    message: []const u8 = "",

    pub fn format(self: Diagnostic, w: *std.Io.Writer) std.Io.Writer.Error!void {
        if (self.line != 0) try w.print("line {d}: ", .{self.line});
        try w.writeAll(self.message);
    }
};

pub const Node = union(enum) {
    scalar: []const u8,
    map: Map,

    pub const Map = std.StringArrayHashMapUnmanaged(Node);
};

pub const Command = struct {
    /// Script run in the server's repo root: with `sh -c`, or on a Windows server as a `.cmd`
    /// batch file (so `%%i` in for loops, `exit /b N`, and `call` for other batch files).
    run: []const u8,
    /// Server ports made reachable on the client's localhost while the command runs.
    forward: []const Forward = &.{},
};

pub const Forward = struct {
    local: u16,
    remote: u16,
};

/// `8080`, `8080, 3000` or `8081:8080` (local:remote).
pub fn parse_forwards(arena: Allocator, text: []const u8) ![]const Forward {
    var list: std.ArrayList(Forward) = .empty;
    var it = std.mem.tokenizeAny(u8, text, ", ");
    while (it.next()) |item| {
        const fwd: Forward = if (std.mem.indexOfScalar(u8, item, ':')) |colon| .{
            .local = try parse_port(item[0..colon]),
            .remote = try parse_port(item[colon + 1 ..]),
        } else blk: {
            const port = try parse_port(item);
            break :blk .{ .local = port, .remote = port };
        };
        for (list.items) |existing| {
            if (existing.local == fwd.local) return error.DuplicatePort;
        }
        try list.append(arena, fwd);
    }
    if (list.items.len == 0) return error.InvalidPort;
    return list.items;
}

fn parse_port(text: []const u8) !u16 {
    const port = std.fmt.parseInt(u16, text, 10) catch return error.InvalidPort;
    if (port == 0) return error.InvalidPort;
    return port;
}

pub const Config = struct {
    address: []const u8 = "127.0.0.1",
    port: u16 = 8099,
    listen: []const u8 = "127.0.0.1",
    /// Largest file `rmtbuild serve` accepts.
    max_payload_mb: u32 = 256,
    /// In file order.
    commands: std.StringArrayHashMapUnmanaged(Command) = .empty,

    /// Everything is allocated in `arena`.
    pub fn parse(arena: Allocator, text: []const u8, diag: *Diagnostic) !Config {
        const root = try parse_yaml(arena, text, diag);

        var config: Config = .{};
        var it = root.iterator();
        while (it.next()) |entry| {
            const key = entry.key_ptr.*;
            if (std.mem.eql(u8, key, "server")) {
                try config.parse_server(arena, entry.value_ptr.*, diag);
            } else if (std.mem.eql(u8, key, "commands")) {
                try config.parse_commands(arena, entry.value_ptr.*, diag);
            } else {
                return fail_fmt(arena, diag, "unknown key '{s}', expected 'server' or 'commands'", .{key});
            }
        }
        return config;
    }

    /// Reads `rmtbuild.yaml` in `dir`. `error.FileNotFound` if there isn't one.
    pub fn load(arena: Allocator, io: std.Io, dir: std.Io.Dir, diag: *Diagnostic) !Config {
        const text = try dir.readFileAlloc(io, file_name, arena, .limited(1024 * 1024));
        return parse(arena, text, diag);
    }

    fn parse_server(self: *Config, arena: Allocator, node: Node, diag: *Diagnostic) !void {
        const map = try expect_map(arena, node, "server", diag);
        var it = map.iterator();
        while (it.next()) |entry| {
            const key = entry.key_ptr.*;
            const value = try expect_scalar(arena, entry.value_ptr.*, "server", key, diag);

            if (std.mem.eql(u8, key, "address")) {
                self.address = value;
            } else if (std.mem.eql(u8, key, "listen")) {
                self.listen = value;
            } else if (std.mem.eql(u8, key, "max_payload_mb")) {
                // Payload lengths are u32 on the wire.
                self.max_payload_mb = std.fmt.parseInt(u32, value, 10) catch 0;
                if (self.max_payload_mb == 0 or self.max_payload_mb > 4095)
                    return fail_fmt(arena, diag, "server.max_payload_mb: '{s}' isn't a size in MB (1-4095)", .{value});
            } else if (std.mem.eql(u8, key, "port")) {
                self.port = std.fmt.parseInt(u16, value, 10) catch
                    return fail_fmt(arena, diag, "server.port: '{s}' isn't a port number (0-65535)", .{value});
            } else {
                return fail_fmt(arena, diag, "server: unknown key '{s}', expected 'address', 'port', 'listen' or 'max_payload_mb'", .{key});
            }
        }
    }

    fn parse_commands(self: *Config, arena: Allocator, node: Node, diag: *Diagnostic) !void {
        const map = try expect_map(arena, node, "commands", diag);
        var it = map.iterator();
        while (it.next()) |entry| {
            const name = entry.key_ptr.*;
            for (reserved_names) |reserved| {
                if (std.mem.eql(u8, name, reserved))
                    return fail_fmt(arena, diag, "commands: '{s}' is reserved by rmtbuild, pick another name", .{name});
            }
            if (std.mem.startsWith(u8, name, "-"))
                return fail_fmt(arena, diag, "commands: '{s}' can't start with '-'", .{name});

            const path = try std.fmt.allocPrint(arena, "commands.{s}", .{name});
            const fields = try expect_map(arena, entry.value_ptr.*, path, diag);

            var run: ?[]const u8 = null;
            var forward: []const Forward = &.{};
            var field_it = fields.iterator();
            while (field_it.next()) |field| {
                if (std.mem.eql(u8, field.key_ptr.*, "run")) {
                    run = try expect_scalar(arena, field.value_ptr.*, path, "run", diag);
                } else if (std.mem.eql(u8, field.key_ptr.*, "forward")) {
                    const text = try expect_scalar(arena, field.value_ptr.*, path, "forward", diag);
                    forward = parse_forwards(arena, text) catch |err| switch (err) {
                        error.OutOfMemory => return error.OutOfMemory,
                        error.DuplicatePort => return fail_fmt(arena, diag, "{s}.forward: '{s}' uses a local port twice", .{ path, text }),
                        error.InvalidPort => return fail_fmt(arena, diag, "{s}.forward: '{s}' should be ports like '8080', '8080, 3000' or '8081:8080'", .{ path, text }),
                    };
                } else {
                    return fail_fmt(arena, diag, "{s}: unknown key '{s}', expected 'run' or 'forward'", .{ path, field.key_ptr.* });
                }
            }

            const script = run orelse return fail_fmt(arena, diag, "{s}: missing 'run'", .{path});
            if (std.mem.trim(u8, script, " \t\n").len == 0)
                return fail_fmt(arena, diag, "{s}.run is empty", .{path});

            try self.commands.put(arena, name, .{ .run = script, .forward = forward });
        }
    }

    fn expect_map(arena: Allocator, node: Node, path: []const u8, diag: *Diagnostic) !Node.Map {
        return switch (node) {
            .map => |m| m,
            .scalar => |s| if (s.len == 0) .empty else fail_fmt(arena, diag, "{s}: expected nested keys, got '{s}'", .{ path, s }),
        };
    }

    fn expect_scalar(arena: Allocator, node: Node, path: []const u8, key: []const u8, diag: *Diagnostic) ![]const u8 {
        return switch (node) {
            .scalar => |s| s,
            .map => fail_fmt(arena, diag, "{s}.{s}: expected a value, got nested keys", .{ path, key }),
        };
    }
};

fn fail_fmt(arena: Allocator, diag: *Diagnostic, comptime fmt: []const u8, args: anytype) error{ InvalidConfig, OutOfMemory } {
    diag.* = .{ .message = try std.fmt.allocPrint(arena, fmt, args) };
    return error.InvalidConfig;
}

/// Parses the YAML subset into a tree of maps and scalars, allocated in `arena`.
pub fn parse_yaml(arena: Allocator, text: []const u8, diag: *Diagnostic) !Node.Map {
    var lines: std.ArrayList(Line) = .empty;
    var it = std.mem.splitScalar(u8, text, '\n');
    var number: usize = 1;
    while (it.next()) |raw| : (number += 1) {
        const line = std.mem.trimEnd(u8, raw, "\r");
        const indent = std.mem.indexOfNone(u8, line, " ") orelse line.len;
        try lines.append(arena, .{ .number = number, .indent = indent, .raw = line });
    }

    var parser: Parser = .{ .arena = arena, .lines = lines.items, .diag = diag };
    const root = try parser.parse_map(0);

    // parse_map(0) only stops early on a line indented less than 0, which can't happen,
    // so anything left means the first line was indented.
    if (parser.peek()) |line| return parser.fail(line, "unexpected indentation");
    return root;
}

const Line = struct {
    number: usize,
    indent: usize,
    raw: []const u8,

    fn content(self: Line) []const u8 {
        return self.raw[self.indent..];
    }

    /// Blank or comment only.
    fn is_ignorable(self: Line) bool {
        const rest = std.mem.trim(u8, self.content(), " \t");
        return rest.len == 0 or rest[0] == '#';
    }
};

const Value = union(enum) {
    none,
    scalar: []const u8,
    /// `|` keeps one trailing newline, `|-` strips it.
    block: enum { clip, strip },
};

const Parser = struct {
    arena: Allocator,
    lines: []const Line,
    i: usize = 0,
    diag: *Diagnostic,

    /// Next line that isn't blank or a comment, without consuming it.
    fn peek(self: *Parser) ?Line {
        while (self.i < self.lines.len) : (self.i += 1) {
            const line = self.lines[self.i];
            if (!line.is_ignorable()) return line;
        }
        return null;
    }

    fn fail(self: *Parser, line: Line, message: []const u8) error{InvalidConfig} {
        self.diag.* = .{ .line = line.number, .message = message };
        return error.InvalidConfig;
    }

    fn parse_map(self: *Parser, indent: usize) !Node.Map {
        var map: Node.Map = .empty;

        while (self.peek()) |line| {
            if (line.indent < indent) break;
            if (line.indent > indent) return self.fail(line, "unexpected indentation");
            if (line.content()[0] == '\t') return self.fail(line, "tabs can't be used for indentation");
            self.i += 1;

            const content = line.content();
            if (content[0] == '-' and (content.len == 1 or content[1] == ' '))
                return self.fail(line, "lists aren't supported");

            const key, const rest = try self.parse_key(line);
            const node: Node = switch (try self.parse_value(line, rest)) {
                .scalar => |s| .{ .scalar = s },
                .block => |chomp| .{ .scalar = try self.parse_block(indent, chomp == .strip) },
                .none => if (self.peek()) |next| if (next.indent > indent)
                    .{ .map = try self.parse_map(next.indent) }
                else
                    .{ .scalar = "" } else .{ .scalar = "" },
            };

            const gop = try map.getOrPut(self.arena, key);
            if (gop.found_existing) return self.fail(line, "duplicate key");
            gop.value_ptr.* = node;
        }

        return map;
    }

    /// Returns the key and whatever follows its `:`.
    fn parse_key(self: *Parser, line: Line) !struct { []const u8, []const u8 } {
        const content = line.content();

        if (content[0] == '"' or content[0] == '\'') {
            const key, const after = try self.parse_quoted(line, content);
            if (after.len == 0 or after[0] != ':') return self.fail(line, "expected ':' after key");
            return .{ key, after[1..] };
        }

        // The key ends at the first ':' followed by a space or the end of the line,
        // so `url: http://x` splits after `url`.
        var i: usize = 0;
        while (std.mem.indexOfScalarPos(u8, content, i, ':')) |colon| : (i = colon + 1) {
            if (colon + 1 == content.len or content[colon + 1] == ' ' or content[colon + 1] == '\t') {
                const key = std.mem.trimEnd(u8, content[0..colon], " \t");
                if (key.len == 0) return self.fail(line, "empty key");
                if (std.mem.indexOfScalar(u8, key, '#') != null) break;
                return .{ key, content[colon + 1 ..] };
            }
        }
        return self.fail(line, "expected 'key: value'");
    }

    fn parse_value(self: *Parser, line: Line, rest_in: []const u8) !Value {
        const rest = std.mem.trim(u8, rest_in, " \t");
        if (rest.len == 0 or rest[0] == '#') return .none;

        switch (rest[0]) {
            '"', '\'' => {
                const value, const after = try self.parse_quoted(line, rest);
                const trailing = std.mem.trim(u8, after, " \t");
                if (trailing.len != 0 and trailing[0] != '#') return self.fail(line, "unexpected text after quoted value");
                return .{ .scalar = value };
            },
            '|' => {
                const marker_end = std.mem.indexOfAny(u8, rest, " \t") orelse rest.len;
                const marker = rest[0..marker_end];
                const trailing = std.mem.trim(u8, rest[marker_end..], " \t");
                if (trailing.len != 0 and trailing[0] != '#') return self.fail(line, "unexpected text after '|'");
                if (std.mem.eql(u8, marker, "|")) return .{ .block = .clip };
                if (std.mem.eql(u8, marker, "|-")) return .{ .block = .strip };
                return self.fail(line, "only '|' and '|-' block scalars are supported");
            },
            '>' => return self.fail(line, "folded '>' blocks aren't supported, use '|'"),
            '[', '{' => return self.fail(line, "flow style '[...]' / '{...}' isn't supported"),
            '&', '*', '!' => return self.fail(line, "anchors, aliases and tags aren't supported"),
            else => {
                // A plain value runs until a ' #' comment.
                var end = rest.len;
                var i: usize = 1;
                while (i < rest.len) : (i += 1) {
                    if (rest[i] == '#' and (rest[i - 1] == ' ' or rest[i - 1] == '\t')) {
                        end = i;
                        break;
                    }
                }
                return .{ .scalar = std.mem.trimEnd(u8, rest[0..end], " \t") };
            },
        }
    }

    /// `text` starts with the opening quote. Returns the value and the text after the closing quote.
    fn parse_quoted(self: *Parser, line: Line, text: []const u8) !struct { []const u8, []const u8 } {
        const quote = text[0];
        var out: std.ArrayList(u8) = .empty;

        var i: usize = 1;
        while (i < text.len) : (i += 1) {
            const c = text[i];
            if (quote == '\'' and c == '\'') {
                // '' is an escaped single quote.
                if (i + 1 < text.len and text[i + 1] == '\'') {
                    try out.append(self.arena, '\'');
                    i += 1;
                    continue;
                }
                return .{ out.items, text[i + 1 ..] };
            }
            if (quote == '"' and c == '"') return .{ out.items, text[i + 1 ..] };
            if (quote == '"' and c == '\\') {
                i += 1;
                if (i == text.len) break;
                try out.append(self.arena, switch (text[i]) {
                    '\\' => '\\',
                    '"' => '"',
                    'n' => '\n',
                    't' => '\t',
                    'r' => '\r',
                    '0' => 0,
                    else => return self.fail(line, "unsupported escape in double quoted string"),
                });
                continue;
            }
            try out.append(self.arena, c);
        }
        return self.fail(line, "unterminated quoted string");
    }

    /// Lines after a `|`, indented deeper than the key. Indentation of the first line is
    /// removed from all of them, comments are kept as content.
    fn parse_block(self: *Parser, key_indent: usize, strip: bool) ![]const u8 {
        var out: std.ArrayList(u8) = .empty;
        var block_indent: ?usize = null;
        var pending_newlines: usize = 0;

        while (self.i < self.lines.len) : (self.i += 1) {
            const line = self.lines[self.i];
            const blank = std.mem.trim(u8, line.raw, " ").len == 0;

            if (blank) {
                if (block_indent != null) pending_newlines += 1;
                continue;
            }
            if (line.indent <= key_indent) break;

            const indent = block_indent orelse blk: {
                if (line.content()[0] == '\t') return self.fail(line, "tabs can't be used for indentation");
                block_indent = line.indent;
                break :blk line.indent;
            };
            if (line.indent < indent) return self.fail(line, "block line is indented less than the first line");

            if (out.items.len != 0) pending_newlines += 1;
            try out.appendNTimes(self.arena, '\n', pending_newlines);
            pending_newlines = 0;
            try out.appendSlice(self.arena, line.raw[indent..]);
        }

        if (!strip and out.items.len != 0) try out.append(self.arena, '\n');
        return out.items;
    }
};

fn test_parse(arena: Allocator, text: []const u8) !Config {
    var diag: Diagnostic = .{};
    return Config.parse(arena, text, &diag) catch |err| {
        std.debug.print("unexpected config error: {f}\n", .{diag});
        return err;
    };
}

fn expect_config_error(text: []const u8, line: usize, message_part: []const u8) !void {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var diag: Diagnostic = .{};
    try std.testing.expectError(error.InvalidConfig, Config.parse(arena.allocator(), text, &diag));
    if (std.mem.indexOf(u8, diag.message, message_part) == null) {
        std.debug.print("expected '{s}' in '{s}'\n", .{ message_part, diag.message });
        return error.TestUnexpectedResult;
    }
    try std.testing.expectEqual(line, diag.line);
}

test "Config full example" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const config = try test_parse(arena.allocator(),
        \\# rmtbuild settings
        \\server:
        \\  address: 192.168.1.20  # build box
        \\  port: 9000
        \\  listen: "0.0.0.0"
        \\  max_payload_mb: 64
        \\
        \\commands:
        \\  build:
        \\    run: zig build -Doptimize=ReleaseFast
        \\  test:
        \\    run: |
        \\      zig build test
        \\
        \\      echo "done" # kept, it's part of the script
        \\  quoted:
        \\    run: 'echo ''hi'' # not a comment'
        \\  url:
        \\    run: curl http://example.com/#frag
        \\  web:
        \\    run: python3 -m http.server 8080
        \\    forward: 8080, 3001:3000
        \\
    );

    try std.testing.expectEqualStrings("192.168.1.20", config.address);
    try std.testing.expectEqual(9000, config.port);
    try std.testing.expectEqualStrings("0.0.0.0", config.listen);
    try std.testing.expectEqual(64, config.max_payload_mb);

    try std.testing.expectEqualStrings("build", config.commands.keys()[0]);
    try std.testing.expectEqualStrings("zig build -Doptimize=ReleaseFast", config.commands.get("build").?.run);
    try std.testing.expectEqualStrings("zig build test\n\necho \"done\" # kept, it's part of the script\n", config.commands.get("test").?.run);
    try std.testing.expectEqualStrings("echo 'hi' # not a comment", config.commands.get("quoted").?.run);
    try std.testing.expectEqualStrings("curl http://example.com/#frag", config.commands.get("url").?.run);

    try std.testing.expect(config.commands.get("build").?.forward.len == 0);
    const forward = config.commands.get("web").?.forward;
    try std.testing.expectEqualSlices(Forward, &.{ .{ .local = 8080, .remote = 8080 }, .{ .local = 3001, .remote = 3000 } }, forward);
}

test "Config defaults" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const config = try test_parse(arena.allocator(),
        \\commands:
        \\  build:
        \\    run: |-
        \\      zig build
        \\      ls zig-out
    );

    try std.testing.expectEqualStrings("127.0.0.1", config.address);
    try std.testing.expectEqual(8099, config.port);
    try std.testing.expectEqualStrings("127.0.0.1", config.listen);
    try std.testing.expectEqualStrings("zig build\nls zig-out", config.commands.get("build").?.run);

    const empty = try test_parse(arena.allocator(), "# nothing yet\n");
    try std.testing.expect(empty.commands.count() == 0);
}

test "Config errors" {
    try expect_config_error("server:\n\tport: 1\n", 2, "tabs");
    try expect_config_error("commands:\n  - build\n", 2, "lists");
    try expect_config_error("commands:\n  a:\n    run: x\n  a:\n    run: y\n", 4, "duplicate");
    try expect_config_error("  server:\n    port: 1\n", 1, "indentation");
    try expect_config_error("server:\n  port: 1\n    extra: 2\n", 3, "indentation");
    try expect_config_error("server: [1, 2]\n", 1, "flow style");
    try expect_config_error("server:\n  port: \"1\n", 2, "unterminated");
    try expect_config_error("just text\n", 1, "key: value");

    try expect_config_error("server:\n  port: 70000\n", 0, "server.port");
    try expect_config_error("server:\n  max_payload_mb: 5000\n", 0, "max_payload_mb");
    try expect_config_error("server:\n  prot: 1\n", 0, "unknown key 'prot'");
    try expect_config_error("comands:\n  build:\n    run: x\n", 0, "unknown key 'comands'");
    try expect_config_error("commands:\n  serve:\n    run: x\n", 0, "reserved");
    try expect_config_error("commands:\n  build:\n    cmd: x\n", 0, "unknown key 'cmd'");
    try expect_config_error("commands:\n  build:\n", 0, "missing 'run'");
    try expect_config_error("commands:\n  web:\n    run: x\n    forward: http\n", 0, "should be ports");
    try expect_config_error("commands:\n  web:\n    run: x\n    forward: 0\n", 0, "should be ports");
    try expect_config_error("commands:\n  web:\n    run: x\n    forward: 8080, 8080:9000\n", 0, "local port twice");
    try expect_config_error("commands:\n  build: zig build\n", 0, "expected nested keys");
}
