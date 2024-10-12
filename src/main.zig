const std = @import("std");
const c = @import("./c.zig");

pub const std_options: std.Options = .{ .log_level = .info };

const debug = std.debug;
const fs = std.fs;
const io = std.io;
const log = std.log;
const math = std.math;
const mem = std.mem;
const process = std.process;
const time = std.time;

const assert = debug.assert;
const eql = mem.eql;
const exit = process.exit;
const panic = debug.panic;
const sleep = time.sleep;

const errnoToString = @import("./errors.zig").errnoToString;
const openFileAbsolute = fs.openFileAbsolute;
const signalToString = @import("./errors.zig").signalToString;

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
) void {
    var signal_set: c.sigset_t = undefined;
    if (c.sigemptyset(&signal_set) == -1) {
        return panic(
            "sigemptyset() = {s}",
            .{errnoToString(errno())},
        );
    }

    if (c.sigaddset(&signal_set, signal) == -1) {
        panic("sigaddset() {s}", .{errnoToString(errno())});
    }

    const act = c.struct_sigaction{
        .__sigaction_handler = .{ .sa_handler = c.SIG_IGN },
        .sa_mask = signal_set,
        .sa_flags = 0,
    };

    if (c.sigaction(signal, &act, null) == -1) {
        panic("sigaction() {s}", .{errnoToString(errno())});
    }
}

fn defaultSignal(signal: c_int) void {
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
        const pgrp = c.getpgrp();
        setForeground(tty.handle, pgrp);
    }

    if (running_pid) |pid_| {
        const pid: c.pid_t = @intCast(pid_);
        running_pid = null;
        const sigchld_pid = info.*._sifields._sigchld.si_pid;

        if (sigchld_pid != pid) {
            panic("unexpected child signal pid => {}", .{sigchld_pid});
        }

        var wstatus: c_int = undefined;

        if (c.waitpid(pid, &wstatus, 0) == -1) { // FIX:
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

var tty: fs.File = undefined;
var stdout: fs.File = undefined;

const CONFIG = struct {
    pub var clear: bool = false;
};

pub fn main() !void {
    { // globals

        GPA.setRequestedMemoryLimit(
            5000,
        );

        tty = openFileAbsolute("/dev/tty", .{}) catch |err| {
            log.err("failed to open /dev/tty", .{});
            panic("open /dev/tty = {s}", .{@errorName(err)});
        };

        stdout = io.getStdOut();
    }

    { // sig handler
        var block_chld = c.sigset_t{};
        if (c.sigemptyset(&block_chld) == -1) {
            panic(
                "sigemptyset() = {s}",
                .{errnoToString(errno())},
            );
        }

        if (c.sigaddset(&block_chld, c.SIGCHLD) == -1) {
            panic(
                "sigaddset() = {s}",
                .{errnoToString(errno())},
            );
        }

        var action = c.struct_sigaction{
            .__sigaction_handler = .{
                .sa_sigaction = sigchld_handler,
            },
            .sa_mask = block_chld,
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

        while (raw_args.next()) |arg| {
            if (mem.eql(u8, arg, "--clear")) {
                CONFIG.clear = true;
            } else {
                args.append(arg) catch unreachable;
            }
        }
        const command_start_idx = for (args.items, 0..) |arg, idx| {
            if (eql(u8, arg, "-c")) break idx;
        } else {
            log.err(
                \\command required
                \\Usage: watchfile <files...> -c <command...>
            , .{});
            exit(1);
        };

        if (command_start_idx + 1 == args.items.len) {
            log.err("Command(-c) argument required", .{});
            exit(1);
        }

        const files = args.items[0..command_start_idx];
        const cmd_string = args.items[command_start_idx + 1 ..];

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
            error.AccessDenied => {
                log.err(
                    "'{s}' Permission denied ",
                    .{filename},
                );
                continue;
            },
            error.FileNotFound => {
                log.debug(
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

    const thread = try std.Thread.spawn(.{}, rerun_loop, .{cmd_string});
    defer thread.join();

    listen(fd, &filemap);
}

var should_restart_lock = std.Thread.Mutex{};
var should_restart = false;

const DELAY_MS = 350;

fn rerun_loop(args: []const []const u8) void {
    while (true) {
        const restart = blk: {
            should_restart_lock.lock();
            defer should_restart_lock.unlock();

            const result = should_restart;
            should_restart = false;
            break :blk result;
        };

        if (restart) {
            log.debug("restart", .{});
            stopRunningProcess();
            startProcess(args, gpa) catch panic("unexpected error", .{});
        }

        sleep(time.ns_per_ms * DELAY_MS);
    }
}

const WatchFile = struct {
    filename: []const u8,
    mask: u32,
};

/// listen for file changes
fn listen(
    fd: c_int,
    filemap: *std.AutoHashMap(c_int, WatchFile),
) void {
    const NUM_EVENTS = 25;
    const EVENT_SIZE = @sizeOf(std.os.linux.inotify_event);

    const buffer = std.heap.page_allocator.alloc(
        u8,
        (NUM_EVENTS * EVENT_SIZE),
    ) catch unreachable; // FIX: read has variable bytes

    while (true) {
        defer {
            should_restart_lock.lock();
            if (should_restart) {
                should_restart = true;
            }
            should_restart_lock.unlock();
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
            log.debug("event: {}", .{evt});

            if (std.os.linux.IN.DELETE_SELF == evt.mask) {
                const kv = filemap.fetchRemove(evt.wd) orelse unreachable;

                const watchfile = kv.value;

                const wd = std.posix.inotify_add_watch(
                    fd,
                    watchfile.filename,
                    watchfile.mask,
                ) catch |err| {
                    switch (err) {
                        error.FileNotFound => {
                            log.warn("file deleted: {s}", .{
                                watchfile.filename,
                            });
                            continue;
                        },
                        else => unreachable,
                    }
                };

                filemap.putNoClobber(wd, watchfile) catch unreachable;
            }

            if (std.os.linux.IN.DELETE_SELF == evt.mask or
                std.os.linux.IN.MODIFY == evt.mask or
                std.os.linux.IN.MOVE_SELF == evt.mask)
            {
                should_restart = true;
            }
        }
    }
}

var running_pid: ?u32 = null;

pub fn setForeground(
    fd: c_int,
    pgrp: c.pid_t,
) void {
    ignoreSignal(c.SIGTTOU);
    defer defaultSignal(c.SIGTTOU);

    if (c.tcsetpgrp(fd, pgrp) == -1) {
        panic("tcsetpgrp({}) = {s}", .{ fd, errnoToString(errno()) });
    }
}

pub fn stopRunningProcess() void {
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

    if (running_pid) |pid| {
        const pgrp: c.pid_t = @intCast(pid);
        running_pid = null;

        { // kill
            log.debug("killpg({})", .{pid});

            if (c.killpg(pgrp, c.SIGKILL) == -1) {
                panic("killpg({}) = {s}", .{ pgrp, errnoToString(errno()) });
            }

            var wstatus: c_int = undefined;
            if (c.waitpid(pgrp, &wstatus, 0) == -1) {
                panic("waitpid({}) = {s}", .{
                    pgrp,
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
                panic("unexpected caught signal; process stopped {}", .{pgrp});
            } else if (c.WIFCONTINUED(wstatus)) {
                panic("unexpected caught signal; process continued {}", .{pgrp});
            }
        }
    }

    { // unblock

        if (c.sigprocmask(c.SIG_SETMASK, &saved, null) !=
            0)
        {
            panic(
                "sigprocmask() = {s}",
                .{errnoToString(errno())},
            );
        }
    }
}

fn blockSignal(sig: c_int) c.sigset_t {
    var mask = c.sigset_t{};
    var original: c.sigset_t = undefined;

    if (c.sigemptyset(&mask) != 0) {
        log.debug(
            "sigemptyset() = {s}",
            .{errnoToString(errno())},
        );
        exit(1);
    }

    if (c.sigaddset(&mask, sig) != 0) {
        log.debug(
            "sigaddset() = {s}",
            .{errnoToString(errno())},
        );
        exit(1);
    }

    if (c.sigprocmask(c.SIG_BLOCK, &mask, &original) != 0) {
        log.debug(
            "sigprocmask() = {s}",
            .{errnoToString(errno())},
        );
        exit(1);
    }

    return original;
}

pub fn startProcess(
    args: []const []const u8,
    allocator: std.mem.Allocator,
) error{UnexpectedError}!void {
    const restore_mask = blockSignal(c.SIGUSR2);

    const state = fork() catch return error.UnexpectedError;

    switch (state) {
        .parent => |pid| {
            running_pid = @intCast(pid);

            { //
                if (c.setpgid(pid, pid) == -1) {
                    log.err("parent failed to create process group", .{});
                    panic(
                        "setpgid({},{}) => ",
                        .{ pid, errno() },
                    );
                }
                setForeground(tty.handle, pid);
            }

            if (c.kill(pid, c.SIGUSR2) != 0) {
                log.debug("kill() = {s}", .{errnoToString(errno())});
                return error.UnexpectedError;
            }
        },
        .child => {
            { //
                if (c.setpgid(0, 0) == -1) {
                    log.debug(
                        "setpgid({}) = {} {s} ",
                        .{
                            c.getpid(),
                            errno(),
                            errnoToString(errno()),
                        },
                    );
                    return error.UnexpectedError;
                }

                setForeground(tty.handle, c.getpid());
            }

            { // wait parent
                const no_op = (&struct {
                    fn f(
                        _: c_int,
                        _: [*c]c.siginfo_t,
                        _: ?*anyopaque,
                    ) callconv(.C) void {}
                }.f);

                setSignal(c.SIGUSR2, no_op) catch unreachable;

                var mask = c.sigset_t{};
                if (c.sigfillset(&mask) != 0) {
                    panic("sigfillset = {s}", .{errnoToString(errno())});
                }
                if (c.sigdelset(&mask, c.SIGUSR2) != 0) {
                    panic("sigdelset = {s}", .{errnoToString(errno())});
                }

                _ = c.sigsuspend(&mask);
                if (errno() != c.EINTR) unreachable;
            }

            defaultSignal(c.SIGINT);
            defaultSignal(c.SIGQUIT);
            defaultSignal(c.SIGTSTP);
            defaultSignal(c.SIGTTIN);
            defaultSignal(c.SIGTTOU);
            defaultSignal(c.SIGCHLD);

            // exec
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

            if (CONFIG.clear) {
                clearScreen();
            }

            _ = c.execvp(cmd_name.ptr, @ptrCast(cmd_args.items.ptr));
            const e = errno();

            switch (e) {
                c.ENOENT => log.warn(
                    "Skip: '{s}' does not exist.",
                    .{cmd_name},
                ),
                else => panic(
                    "failed to run executable = {s}",
                    .{errnoToString(e)},
                ),
            }
            exit(1);
        },
    }

    if (c.sigprocmask(c.SIG_SETMASK, &restore_mask, null) != 0) {
        log.err("sigprocmask = {s}", .{errnoToString(errno())});
        return error.UnexpectedError;
    }
}

///
fn clearScreen() void {
    io.getStdOut().writeAll("\u{1b}[2J\u{1b}[H") catch |err| {
        panic("unable to write to standard output {s}", .{
            @errorName(err),
        });
    };
}

///
fn eraseLine() void {
    io.getStdOut().writeAll("\u{1b}[1K\u{0D}") catch |err|
        panic("unable to write to standard output {s}", .{@errorName(err)});
}

///
fn print(comptime fmt: []const u8, args: anytype) void {
    std.fmt.format(stdout.writer(), fmt, args) catch |err|
        panic("stdout {s}", .{@errorName(err)});

    stdout.writeAll("\n") catch |err|
        panic("stdout {s}", .{@errorName(err)});
}
