//! Byte pipe for port forwarding, used by both ends of an RMT_FWD connection.
const std = @import("std");
const net = std.Io.net;

/// Copies `a` <-> `b` until both directions have finished. `a_reader` is a reader already
/// on `a`, anything it buffered past the RMT_FWD packet is forwarded first.
/// An end of stream in one direction is passed on as a half close, so request/response
/// protocols that close their sending side still work.
pub fn pipe(io: std.Io, a: net.Stream, a_reader: *std.Io.Reader, b: net.Stream) void {
    const back = std.Thread.spawn(.{}, copy_from_stream, .{ io, b, a }) catch {
        // Can't run both directions, give up on this connection rather than half work.
        return;
    };
    copy(io, a_reader, b);
    back.join();
}

fn copy_from_stream(io: std.Io, from: net.Stream, to: net.Stream) void {
    var buf: [16 * 1024]u8 = undefined;
    var reader = from.reader(io, &buf);
    copy(io, &reader.interface, to);
}

fn copy(io: std.Io, from: *std.Io.Reader, to: net.Stream) void {
    var wbuf: [256]u8 = undefined;
    var writer = to.writer(io, &wbuf);
    const w = &writer.interface;

    while (true) {
        if (from.bufferedLen() == 0) from.fillMore() catch break;
        const data = from.buffered();
        // Flush every read so interactive traffic isn't held back waiting for a full buffer.
        w.writeAll(data) catch break;
        w.flush() catch break;
        from.toss(data.len);
    }

    to.shutdown(io, .send) catch {};
}
