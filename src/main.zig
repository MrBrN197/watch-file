const std = @import("std");

const c = @import("./c.zig");

const errnoToString = @import("./errors.zig").errnoToString;
const signalToString = @import("./errors.zig").signalToString;

pub const std_options: std.Options = .{ .log_level = .info };

const debug = std.debug;
const fs = std.fs;
const log = std.log;
const math = std.math;
const mem = std.mem;
const process = std.process;
const time = std.time;

const assert = debug.assert;
const eql = mem.eql;
const exit = process.exit;
const openFileAbsolute = fs.openFileAbsolute;
const panic = debug.panic;

var GPA = std.heap.GeneralPurposeAllocator(.{
    .enable_memory_limit = true,
}){};
const gpa = GPA.allocator();

fn errno() c_int {
    return c.__errno_location().*;
}

fn fork() error{ForkFailure}!union(enum) {
    child: void,
    parent: c_int,
} {
    const status = c.fork();
    if (status == -1) return error.ForkFailure;

    if (status == 0) {
        return .child;
    } else {
        return .{ .parent = status };
    }
}

fn ignoreSignal(
    signal: c_int,
) !void {
    var signal_set: c.sigset_t = undefined;
    if (c.sigemptyset(&signal_set) == -1) {
        return panic(
            "failed to set filled signal set = {s}",
            .{errnoToString(errno())},
        );
    }

    if (c.sigaddset(&signal_set, signal) == -1) {
        return error.SigAddFailure;
    }

    const act = c.struct_sigaction{
        .__sigaction_handler = .{ .sa_handler = c.SIG_IGN },
        .sa_mask = signal_set,
        .sa_flags = 0,
    };

    if (c.sigaction(signal, &act, null) == -1) {
        return error.SigactionFailure;
    }
}

fn defaultSignal(
    signal: c_int,
) void {
    var signal_set: c.sigset_t = undefined;
    if (c.sigemptyset(&signal_set) == -1) {
        panic("sigemptyset() = {}", .{errno()});
    }

    if (c.sigaddset(&signal_set, signal) == -1) {
        panic("sigaddset() = {}", .{errno()});
    }

    const act = c.struct_sigaction{
        .__sigaction_handler = .{ .sa_handler = c.SIG_DFL },
        .sa_mask = signal_set,
        .sa_flags = 0,
    };

    if (c.sigaction(signal, &act, null) == -1) {
        panic("sigaction({}, {}) = {}", .{ signal, act.sa_flags, errno() });
    }
}

fn setSignal(
    signal: c_int,
    handler: ?*const fn (
        c_int,
        [*c]c.siginfo_t,
        ?*anyopaque,
    ) callconv(.C) void,
) !void {
    var signal_set: c.sigset_t = undefined;
    if (c.sigemptyset(&signal_set) == -1) {
        return panic(
            "failed to set filled signal set = {s}",
            .{errnoToString(errno())},
        );
    }

    if (c.sigaddset(&signal_set, signal) == -1) {
        return error.SigAddFailure;
    }

    const act = c.struct_sigaction{
        .__sigaction_handler = .{ .sa_sigaction = handler },
        .sa_mask = signal_set,
        .sa_flags = 0,
    };

    if (c.sigaction(signal, &act, null) == -1) {
        return error.SigactionFailure;
    }
}

fn sigchld_handler(
    _: c_int,
    info: [*c]c.siginfo_t,
    _: ?*anyopaque,
) callconv(.C) void {
    { //
        ignoreSignal(c.SIGTTOU) catch panic(
            "failed to set signal",
            .{},
        );
        defer defaultSignal(c.SIGTTOU);

        const pgrp = c.getpgrp();
        setForeground(tty.handle, pgrp);
    }

    if (running_pid) |pid_| {
        const pid: c.pid_t = @intCast(pid_);
        running_pid = null;

        if (info.*._sifields._sigchld.si_pid != pid)
            return;

        var wstatus: c_int = undefined;

        if (c.waitpid(-pid, &wstatus, 0) == -1) { // FIX:
            log.err("unexpected error", .{});
            panic(
                "[signal] waitpid({}) = {}",
                .{ pid, errno() },
            );
            exit(1);
        }

        if (c.WIFEXITED(wstatus)) {
            const exit_status = c.WEXITSTATUS(wstatus);
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

var tty: std.fs.File = undefined;
var devnull: std.fs.File = undefined;
var stdout: std.fs.File = undefined;

pub fn main() !void {
    { // globals

        GPA.setRequestedMemoryLimit(
            5000,
        );

        tty = openFileAbsolute("/dev/tty", .{}) catch |err| {
            log.err("failed to open /dev/tty", .{});
            panic("open /dev/tty = {s}", .{@errorName(err)});
        };

        devnull = openFileAbsolute("/dev/null", .{}) catch
            unreachable;

        stdout = std.io.getStdOut();
    }

    { // sig handler
        var blockAll = c.sigset_t{};
        if (c.sigemptyset(&blockAll) == -1) {
            panic(
                "sigfillset() = {s}",
                .{errnoToString(errno())},
            );
        }

        if (c.sigaddset(&blockAll, c.SIGCHLD) == -1) {
            panic(
                "sigaddset() = {s}",
                .{errnoToString(errno())},
            );
        }

        var action = c.struct_sigaction{
            .__sigaction_handler = .{
                .sa_sigaction = sigchld_handler,
            },
            .sa_mask = blockAll,
            .sa_flags = c.SA_SIGINFO,
        };

        if (c.sigaction(c.SIGCHLD, &action, null) != 0) {
            panic(
                "[error]sigaction() = {s}",
                .{errnoToString(errno())},
            );
        }
    }

    const files, const cmd_string = args: {
        var raw_args = process.args();
        assert(raw_args.skip());

        var args = std.ArrayList([]const u8).init(gpa);

        while (raw_args.next()) |arg| args.append(arg) catch unreachable;

        const found = for (args.items, 0..) |arg, idx| {
            if (eql(u8, arg, "-c")) break idx;
        } else {
            log.err(
                \\command required
                \\Usage: watchfile <files...> -c <command...>
            , .{});
            exit(1);
        };

        if (found + 1 == args.items.len) {
            log.err("Command(-c) argument required", .{});
            exit(1);
        }

        const files = args.items[0..found];
        const cmd_string = args.items[found + 1 ..];

        if (files.len == 0) {
            log.err("files required", .{});
            log.info("Usage: watchfile <files...> -c <command...>", .{});
            exit(1);
        }
        break :args .{ files, cmd_string };
    };

    const notify_flags = std.os.linux.IN.CLOEXEC;

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
        error.SystemResources => {
            log.err("unavailable resources", .{}); // TODO:
            exit(1);
        },
        else => {
            panic("unexpected error: {s}", .{@errorName(err)});
        },
    };

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
            error.FileNotFound => {
                log.warn(
                    "'{s}' doesn't exist",
                    .{filename},
                );
                continue;
            },
            else => {
                log.err(
                    "unexpected error \nskipping {s}",
                    .{@errorName(err)},
                );

                continue;
            },
        };

        print("=> {s:>20} ({})", .{ filename, wd });

        filemap.putNoClobber(wd, WatchFile{
            .filename = filename,
            .mask = mask,
        }) catch unreachable;
    }

    if (filemap.count() == 0) {
        log.err("** no files to watch **", .{});
        exit(1);
    }

    start(fd, &filemap, cmd_string);
}

const WatchFile = struct {
    filename: []const u8,
    mask: u32,
};

/// thread listener for file changes
fn start(
    fd: c_int,
    filemap: *std.AutoHashMap(c_int, WatchFile),
    args: []const []const u8,
) void {
    const NUM_EVENTS = 24;
    const EVENT_SIZE = @sizeOf(std.os.linux.inotify_event);

    const buffer = std.heap.page_allocator.alloc(
        u8,
        (NUM_EVENTS * EVENT_SIZE),
    ) catch unreachable; // FIX: read has variable bytes

    while (true) {
        var should_run_command = false;

        defer {
            if (should_run_command) {
                runCommand(args, gpa);
            }
        }

        const size = std.posix.read(fd, buffer) catch |err|
            switch (err) {
            error.WouldBlock => {
                log.err("unexpected non-blocking on file descriptor", .{});
                exit(1);
            },
            else => {
                log.err(
                    "unexpected error reading watched event = {s}",
                    .{@errorName(err)},
                );
                exit(1);
            },
        };

        assert(@mod(size, EVENT_SIZE) == 0);

        const num_events: usize = @as(usize, @intCast(size)) / EVENT_SIZE;

        for (0..num_events) |event_idx| {
            const evt: *const std.os.linux.inotify_event = @ptrFromInt(
                @intFromPtr(buffer.ptr) + (EVENT_SIZE * event_idx),
            );

            log.debug("event: [mask:{b:>32}]", .{evt.mask});

            if (std.os.linux.IN.DELETE_SELF == evt.mask) {
                const kv = filemap.fetchRemove(evt.wd) orelse unreachable;

                const watchfile = kv.value;
                print("deleted: {s}", .{watchfile.filename});

                const wd = std.posix.inotify_add_watch(
                    fd,
                    watchfile.filename,
                    watchfile.mask,
                ) catch unreachable;

                filemap.putNoClobber(wd, watchfile) catch unreachable;
            }

            if (std.os.linux.IN.DELETE_SELF == evt.mask or
                std.os.linux.IN.MODIFY == evt.mask or
                std.os.linux.IN.MOVE_SELF == evt.mask)
            {
                should_run_command = true;
            }
        }
    }
}

var running_pid: ?u32 = null;

pub fn setForeground(
    fd: c_int,
    pgrp: c.pid_t,
) void {
    if (c.tcsetpgrp(fd, pgrp) == -1) {
        panic("tcsetpgrp({}) = {s}", .{ fd, errnoToString(errno()) });
    }
}

pub fn runCommand(
    args: []const []const u8,
    allocator: std.mem.Allocator,
) void {
    const saved = blk: { // block
        var blocked = c.sigset_t{};
        if (c.sigemptyset(&blocked) != 0) {
            panic("sigemptyset", .{});
            exit(1);
        }
        if (c.sigaddset(&blocked, c.SIGCHLD) != 0) {
            panic("sigaddset", .{});
            exit(1);
        }

        var saved_ = c.sigset_t{};
        if (c.sigprocmask(
            c.SIG_BLOCK,
            &blocked,
            &saved_,
        ) != 0) {
            log.err("failed to block signal", .{});
            panic(
                "sigprocmask() = {s}",
                .{errnoToString(errno())},
            );
        }
        break :blk saved_;
    };

    if (running_pid) |pid_| {
        const pid: c.pid_t = @intCast(pid_);
        running_pid = null;

        { // kill
            if (c.kill(pid, c.SIGTERM) == -1) {
                log.debug("kill({}) = {s}", .{ pid, errnoToString(errno()) });
                panic("kill({}) = {s}", .{ pid, errnoToString(errno()) });
            }

            var wstatus: c_int = undefined;
            if (c.waitpid(pid, &wstatus, 0) == -1) {
                panic("waitpid({}) = {s}", .{
                    pid,
                    errnoToString(errno()),
                });
            }

            // if (cc.WIFEXITED(wstatus)) {
            //
            // }
            if (c.WIFSIGNALED(wstatus)) {
                // if (cc.WTERMSIG(wstatus) != cc.SIGKILL) {
                //     log.err("[error]unexpectedly killed by signal = {}", .{cc.WTERMSIG(wstatus)});
                //     panic("[error]unexpectedly killed by signal = {}", .{cc.WTERMSIG(wstatus)});
                // }
            } else if (c.WIFSTOPPED(wstatus)) {
                panic("unexpected caught signal; process stopped {}", .{pid});
            } else if (c.WIFCONTINUED(wstatus)) {
                panic("unexpected caught signal; process continued {}", .{pid});
            }
        }
    }

    { // unblock

        if (c.sigprocmask(c.SIG_SETMASK, &saved, null) !=
            0)
        {
            log.err("sigprocmask", .{});
            panic(
                "sigprocmask() = {s}",
                .{errnoToString(errno())},
            );
        }
    }

    const value = fork() catch {
        log.err("unexpected error executing command", .{});
        panic("unexpected error executing command", .{});
    };

    switch (value) {
        .parent => |pid| {
            running_pid = @intCast(pid);

            if (c.dup2(devnull.handle, 0) == -1) {
                panic("redirect input  = {s}({})", .{
                    errnoToString(errno()),
                    errno(),
                });
            }

            if (c.setpgid(pid, pid) == -1) {
                log.err("parent failed to create process group", .{});
                panic(
                    "setpgid({},{}) => ",
                    .{ pid, errno() },
                );
            }

            setForeground(tty.handle, pid);
        },
        .child => {
            { //
                if (c.setpgid(0, 0) == -1) {
                    panic(
                        "setpgid({}) = {} {s} ",
                        .{
                            c.getpid(),
                            errno(),
                            errnoToString(errno()),
                        },
                    );
                }

                setForeground(tty.handle, c.getpid());
            }

            defaultSignal(c.SIGINT);
            defaultSignal(c.SIGQUIT);
            defaultSignal(c.SIGTSTP);
            defaultSignal(c.SIGTTIN);
            defaultSignal(c.SIGTTOU);
            defaultSignal(c.SIGCHLD);

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
                clearScreen();
                _ = c.execvp(cmd_name.ptr, @ptrCast(cmd_args.items.ptr));
                switch (errno()) {
                    c.ENOENT => log.err(
                        "pathname '{s}' does not exist.",
                        .{cmd_name},
                    ),
                    else => panic(
                        "failed to run executable = {s}",
                        .{errnoToString(errno())},
                    ),
                }
                log.debug(
                    "execvp({s}) = {s}",
                    .{ cmd_name, errnoToString(errno()) },
                );
                exit(1);
            }
        },
    }
}

///
fn clearScreen() void {
    std.io.getStdOut().writeAll("\u{1b}[2J\u{1b}[H") catch |err| {
        panic("unable to write to standard output {s}", .{
            @errorName(err),
        });
    };
}

///
fn eraseLine() void {
    std.io.getStdOut().writeAll("\u{1b}[1K\u{0D}") catch |err|
        panic("unable to write to standard output {s}", .{@errorName(err)});
}

///
fn print(comptime fmt: []const u8, args: anytype) void {
    std.fmt.format(stdout.writer(), fmt, args) catch |err|
        panic("stdout {s}", .{@errorName(err)});

    stdout.writeAll("\n") catch |err|
        panic("stdout {s}", .{@errorName(err)});
}
