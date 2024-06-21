const std = @import("std");

const cc = @cImport({
    @cInclude("errno.h");
    @cInclude("signal.h");
    @cInclude("unistd.h");
    @cInclude("sys/wait.h");
});

const mem = std.mem;
const time = std.time;
const process = std.process;
const math = std.math;
const debug = std.debug;

const assert = debug.assert;
const eql = mem.eql;
const exit = process.exit;
const panic = debug.panic;
const powi = math.powi;
const sleep = time.sleep;

var GPA = std.heap.GeneralPurposeAllocator(.{
    .enable_memory_limit = true,
}){};
const gpa = GPA.allocator();

fn errno() c_int {
    // warn: prevprev != prev;
    return cc.__errno_location().*;
}

fn fork() error{ForkFailure}!union(enum) {
    child: void,
    parent: c_int,
} {
    const status = cc.fork();
    if (status == -1) return error.ForkFailure;

    if (status == 0) {
        return .child;
    } else {
        return .{ .parent = status };
    }
}

fn sigchld_handler(_: c_int) callconv(.C) void {
    // TODO: check pid

    if (running_pid) |pid| {
        running_pid = null;

        var wstatus: c_int = undefined;
        if (cc.waitpid(pid, &wstatus, 0) == -1) {
            print("[signal] waitpid({}) => {}", .{ pid, errno() });
            exit(1);
        }

        if (cc.WIFEXITED(wstatus)) {
            const exit_status = cc.WEXITSTATUS(wstatus);
            if (exit_status == 0)
                print("{s}  Status: {}{s}", .{
                    "\u{1b}[38;5;2m",
                    exit_status,
                    "\u{1b}[m",
                })
            else
                print("{s} ❌Status: {}{s}", .{
                    "\u{1b}[38;5;1m",
                    exit_status,
                    "\u{1b}[m",
                });
        }
    }
}

pub fn main() !void {
    { // sig handler
        var blockAll = cc.sigset_t{};
        if (cc.sigfillset(&blockAll) == -1) {
            panic("sigfillset() => {}", .{errno()});
        }

        if (cc.sigaddset(&blockAll, cc.SIGCHLD) == -1) {
            panic("sigaddset() => {}", .{errno()});
        }

        var action = cc.struct_sigaction{
            .__sigaction_handler = .{
                .sa_handler = sigchld_handler,
            },
            .sa_mask = blockAll,
            .sa_flags = 0,
        };

        if (cc.sigaction(cc.SIGCHLD, &action, null) != 0) {
            panic("[error]sigaction() => {}", .{errno()});
        }
    }

    GPA.setRequestedMemoryLimit(
        powi(usize, 2, 20) catch unreachable,
    );

    const files, const cmd_string = args: {
        var raw_args = process.args();
        assert(raw_args.skip());

        var args = std.ArrayList([]const u8).init(gpa);

        while (raw_args.next()) |arg| args.append(arg) catch unreachable;

        const found = for (args.items, 0..) |arg, idx| {
            if (eql(u8, arg, "-c")) break idx;
        } else {
            print(
                \\command required
                \\Usage: watchfile <files...> -c <command...>
            , .{});
            exit(1);
        };

        if (found + 1 == args.items.len) {
            print(
                \\ "Command(-c) argument required"
            , .{});
            exit(1);
        }

        const files = args.items[0..found];
        const cmd_string = args.items[found + 1 ..];

        if (files.len == 0) {
            const err = "error: files required";
            const usage = "Usage: watchfile <files...> -c <command...>";
            print("{s}{s}", .{ err, usage });
            exit(1);
        }
        break :args .{ files, cmd_string };
    };

    const notify_flags = std.os.linux.IN.CLOEXEC | std.os.linux.IN.NONBLOCK;
    // const fd = c.inotify_init1(c.IN_CLOEXEC);

    const fd = std.posix.inotify_init1(notify_flags) catch |err|
        switch (err) {
        error.ProcessFdQuotaExceeded => panic(
            "error: Process Quota reached --> Too many files to watch",
            .{},
        ),
        error.SystemFdQuotaExceeded => {
            panic(
                "error: Process Quota reached --> Too many files to watch",
                .{},
            );
        },
        error.SystemResources => unreachable,
        else => unreachable,
    };

    // assert(fd != -1); // NOTE: remove

    var filemap = std.AutoHashMap(
        c_int,
        WatchFile,
    ).init(std.heap.page_allocator);

    for (files) |filename| {
        const mask = (std.os.linux.IN.MODIFY |
            std.os.linux.IN.DELETE_SELF |
            std.os.linux.IN.MOVE_SELF);

        const wd = std.posix.inotify_add_watch(fd, filename, mask) catch |err|
            switch (err) {
            error.AccessDenied => @panic("AccessDenined"),
            else => unreachable,
        };

        print("=> {s:>20} ({})", .{ filename, wd });

        filemap.putNoClobber(wd, WatchFile{
            .filename = filename,
            .mask = mask,
        }) catch unreachable;
    }

    listen(fd, &filemap, cmd_string);
}

const WatchFile = struct {
    filename: []const u8,
    mask: u32,
};

/// thread listener for file changes
fn listen(
    fd: c_int,
    filemap: *std.AutoHashMap(c_int, WatchFile),
    args: []const []const u8,
) void {
    const NUM_EVENTS = 10;
    const EVENT_SIZE = @sizeOf(std.os.linux.inotify_event);

    const buffer = std.heap.page_allocator.alloc(
        u8,
        (NUM_EVENTS * EVENT_SIZE),
    ) catch unreachable; // FIX: read has variable bytes

    var i: usize = 0;
    while (true) {
        defer i += 1;

        const size = std.posix.read(
            fd,
            buffer,
        ) catch |err| switch (err) {
            // error. => panic("fdlsajflsd", .{}),
            error.WouldBlock => {
                std.time.sleep(std.time.ns_per_ms * 60);
                continue;
            },
            else => unreachable,
        };

        if (size == -1) {
            const value = errno();
            // if (value == c.EINTR) continue;
            if (value == std.c.EAGAIN) continue;

            .panic("errno({})", .{value});
        }

        const num_events: usize = @as(usize, @intCast(size)) / EVENT_SIZE;

        if (num_events > 8) {
            print("[error]too many changes detected => {}", .{num_events});
            exit(1);
        }

        for (0..num_events) |event_idx| {
            const evt: *std.os.linux.inotify_event = @ptrFromInt(
                @intFromPtr(buffer.ptr) + (EVENT_SIZE * event_idx),
            );

            if (std.os.linux.IN.MODIFY == evt.mask or
                std.os.linux.IN.MOVE_SELF == evt.mask)
            {
                const watchfile = filemap.getPtr(evt.wd).?;
                print("=> {s}", .{watchfile.filename});
                runCommand(args, gpa);
            }

            if (std.os.linux.IN.DELETE_SELF == evt.mask) {
                const kv = filemap.fetchRemove(evt.wd) orelse unreachable;
                const watchfile = kv.value;
                print("=> {s}", .{watchfile.filename});

                const wd = std.posix.inotify_add_watch(
                    fd,
                    watchfile.filename, // FIX: ptr
                    watchfile.mask,
                ) catch unreachable;

                filemap.putNoClobber(wd, watchfile) catch unreachable;
                runCommand(args, gpa);
            }

            if (std.os.linux.IN.IGNORED == evt.mask) {
                // print("-> IN_IGNORED", .{});
            }
        }
    }
}

var running_pid: ?cc.pid_t = null;

pub fn runCommand(
    args: []const []const u8,
    allocator: std.mem.Allocator,
) void {
    const saved = blk: { // block
        var blocked = cc.sigset_t{};
        if (cc.sigemptyset(&blocked) != 0) {
            print("[error] sigemptyset", .{});
            exit(1);
        }
        if (cc.sigaddset(&blocked, cc.SIGCHLD) != 0) {
            print("[error] sigaddset", .{});
            exit(1);
        }

        var saved_ = cc.sigset_t{};
        if (cc.sigprocmask(
            cc.SIG_BLOCK,
            &blocked,
            &saved_,
        ) != 0) {
            print("[error] sigprocmask", .{});
            exit(1);
        }
        break :blk saved_;
    };

    if (running_pid) |pid| {
        running_pid = null;

        { // kill
            if (cc.kill(pid, cc.SIGKILL) == -1) {
                print("kill({}) => {}", .{ pid, errno() });
                exit(1);
            }

            var wstatus: c_int = undefined;
            if (cc.waitpid(pid, &wstatus, 0) == -1) { // WUNTRACED | WCONTINUED);
                panic("waitpid({}) => {}", .{ pid, errno() });
            }

            // if (cc.WIFEXITED(wstatus)) {
            //
            // }
            if (cc.WIFSIGNALED(wstatus)) {
                if (cc.WTERMSIG(wstatus) != cc.SIGKILL) {
                    print("[error]unexpectedly killed by signal => {}", .{cc.WTERMSIG(wstatus)});
                    exit(1);
                }
            } else if (cc.WIFSTOPPED(wstatus)) {
                panic("unexpected caught signal; process stopped {}", .{pid});
            } else if (cc.WIFCONTINUED(wstatus)) {
                panic("unexpected caught signal; process continued {}", .{pid});
            }
        }
    }

    { // unblock

        if (cc.sigprocmask(cc.SIG_SETMASK, &saved, null) !=
            0)
        {
            print("[error] sigprocmask", .{});
            exit(1);
        }
    }

    const value = fork() catch unreachable;

    switch (value) {
        .parent => |pid| {
            running_pid = pid;
        },
        .child => {
            const cmd_name, const cmd_args = blk: { // null termination
                const first_arg = allocator.alloc(
                    u8,
                    args[0].len + 1,
                ) catch unreachable;
                // TODO: sysconf max args

                mem.copyForwards(
                    u8,
                    first_arg,
                    args[0],
                );
                first_arg[args[0].len] = 0;

                const slash_index = mem.lastIndexOfScalar(
                    u8,
                    first_arg,
                    '/',
                ) orelse 0;

                var c_args = std.ArrayList(
                    [*c]const u8,
                ).init(allocator);

                const arg0 = first_arg[slash_index..];
                c_args.append(
                    @ptrCast(arg0.ptr),
                ) catch unreachable;

                for (args[1..]) |arg| {
                    const buf = allocator.alloc(
                        u8,
                        arg.len + 1,
                    ) catch unreachable;

                    mem.copyForwards(u8, buf, arg);
                    buf[arg.len] = 0; // null term

                    c_args.append(@ptrCast(buf.ptr)) catch
                        unreachable;
                }

                c_args.append(null) catch unreachable;
                break :blk .{ first_arg, c_args };
            };

            { // exec

                if (cc.close(std.io.getStdIn().handle) != 0) {
                    print("failed to redirect input fd", .{});
                    exit(1);
                }

                clearScreen();

                _ = cc.execvp(cmd_name.ptr, @ptrCast(cmd_args.items.ptr));
                switch (errno()) {
                    cc.ENOENT => print(
                        "[error] pathname '{s}' does not exist.",
                        .{cmd_name},
                    ),
                    else => print(
                        "[error] failed to run executable => {}",
                        .{errno()},
                    ),
                }
                exit(1);
            }
        },
    }
}

///
fn clearScreen() void {
    debug.print("\u{1b}[2J\u{1b}[H", .{});
}

///
fn eraseLine() void {
    debug.print("\u{1b}[1K\u{0D}", .{});
}

///
fn print(comptime fmt: []const u8, args: anytype) void {
    debug.print(fmt, args);
    debug.print("\n", .{});
}
