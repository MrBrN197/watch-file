const std = @import("std");

const cc = @cImport({
    @cInclude("errno.h");
    @cInclude("signal.h");
    @cInclude("unistd.h");
    @cInclude("sys/wait.h");
});

const errnoToString = @import("./errors.zig").errnoToString;
const signalToString = @import("./errors.zig").signalToString;

const debug = std.debug;
const log = std.log;
const math = std.math;
const mem = std.mem;
const process = std.process;
const time = std.time;

pub const std_options: std.Options = .{ .log_level = .info };

const assert = debug.assert;
const eql = mem.eql;
const exit = process.exit;
const panic = debug.panic;
const powi = math.powi;

var GPA = std.heap.GeneralPurposeAllocator(.{
    .enable_memory_limit = true,
}){};
const gpa = GPA.allocator();

fn errno() c_int {
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

fn ignoreSignal(
    signal: c_int,
) !void {
    var signal_set: cc.sigset_t = undefined;
    if (cc.sigemptyset(&signal_set) == -1) {
        return panic(
            "failed to set filled signal set => {s}",
            .{errnoToString(errno())},
        );
    }

    if (cc.sigaddset(&signal_set, signal) == -1) {
        return error.SigAddFailure;
    }

    const act = cc.struct_sigaction{
        .__sigaction_handler = .{ .sa_handler = cc.SIG_IGN },
        .sa_mask = signal_set,
        .sa_flags = 0,
    };

    if (cc.sigaction(signal, &act, null) == -1) {
        return error.SigactionFailure;
    }
}

fn defaultSignal(
    signal: c_int,
) !void {
    var signal_set: cc.sigset_t = undefined;
    if (cc.sigemptyset(&signal_set) == -1) {
        return panic(
            "failed to set filled signal set => {s}",
            .{errnoToString(errno())},
        );
    }

    if (cc.sigaddset(&signal_set, signal) == -1) {
        return error.SigAddFailure;
    }

    const act = cc.struct_sigaction{
        .__sigaction_handler = .{ .sa_handler = cc.SIG_DFL },
        .sa_mask = signal_set,
        .sa_flags = 0,
    };

    if (cc.sigaction(signal, &act, null) == -1) {
        return error.SigactionFailure;
    }
}

fn setSignal(
    signal: c_int,
    handler: ?*const fn (
        c_int,
        [*c]cc.siginfo_t,
        ?*anyopaque,
    ) callconv(.C) void,
) !void {
    var signal_set: cc.sigset_t = undefined;
    if (cc.sigemptyset(&signal_set) == -1) {
        return panic(
            "failed to set filled signal set => {s}",
            .{errnoToString(errno())},
        );
    }

    if (cc.sigaddset(&signal_set, signal) == -1) {
        return error.SigAddFailure;
    }

    const act = cc.struct_sigaction{
        .__sigaction_handler = .{ .sa_sigaction = handler },
        .sa_mask = signal_set,
        .sa_flags = 0,
    };

    if (cc.sigaction(signal, &act, null) == -1) {
        return error.SigactionFailure;
    }
}

fn sigchld_handler(
    _: c_int,
    info: [*c]cc.siginfo_t,
    _: ?*anyopaque,
) callconv(.C) void {
    {
        ignoreSignal(cc.SIGTTOU) catch panic(
            "failed to set signal",
            .{},
        );
        defer defaultSignal(cc.SIGTTOU) catch panic(
            "failed to set signal",
            .{},
        );

        const pgrp = cc.getpgrp();
        setForeground(tty.handle, pgrp);
    }

    if (running_pid) |pid_| {
        const pid: cc.pid_t = @intCast(pid_);
        running_pid = null;

        if (info.*._sifields._sigchld.si_pid != pid)
            return;

        var wstatus: c_int = undefined;

        if (cc.waitpid(-pid, &wstatus, 0) == -1) { // FIX:
            log.err("[signal] waitpid({}) => {}", .{ pid, errno() });
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

var tty: std.fs.File = undefined;

pub fn main() !void {
    tty = std.fs.openFileAbsolute("/dev/tty", .{}) catch {
        log.err("failed to open /dev/tty", .{});
        panic("open /dev/tty => {}", .{errno()});
        exit(1);
    };

    { // sig handler
        var blockAll = cc.sigset_t{};
        if (cc.sigemptyset(&blockAll) == -1) {
            panic(
                "sigfillset() => {} {s}",
                .{ errno(), errnoToString(errno()) },
            );
        }

        if (cc.sigaddset(&blockAll, cc.SIGCHLD) == -1) {
            panic(
                "sigaddset() => {} {s}",
                .{ errno(), errnoToString(errno()) },
            );
        }

        var action = cc.struct_sigaction{
            .__sigaction_handler = .{
                .sa_sigaction = sigchld_handler,
            },
            .sa_mask = blockAll,
            .sa_flags = cc.SA_SIGINFO,
        };

        if (cc.sigaction(cc.SIGCHLD, &action, null) != 0) {
            panic(
                "[error]sigaction() => {} {s}",
                .{ errno(), errnoToString(errno()) },
            );
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
        error.SystemResources => unreachable,
        else => unreachable,
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

        log.info("=> {s:>20} ({})", .{ filename, wd });

        filemap.putNoClobber(wd, WatchFile{
            .filename = filename,
            .mask = mask,
        }) catch unreachable;
    }

    if (filemap.count() == 0) {
        print("** no files to watch **", .{});
        exit(1);
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
    const NUM_EVENTS = 24;
    const EVENT_SIZE = @sizeOf(std.os.linux.inotify_event);

    const buffer = std.heap.page_allocator.alloc(
        u8,
        (NUM_EVENTS * EVENT_SIZE),
    ) catch unreachable; // FIX: read has variable bytes

    while (true) {
        const size = std.posix.read(fd, buffer) catch |err|
            switch (err) {
            error.WouldBlock => {
                log.err("unexpected non-blocking on file descriptor", .{});
                exit(1);
            },
            else => {
                log.err(
                    "unexpected error reading watched event => {s}",
                    .{@errorName(err)},
                );
                exit(1);
            },
        };

        const num_events: usize = @as(usize, @intCast(size)) / EVENT_SIZE;

        var should_run_command = false;

        for (0..num_events) |event_idx| {
            const evt: *const std.os.linux.inotify_event = @ptrFromInt(
                @intFromPtr(buffer.ptr) + (EVENT_SIZE * event_idx),
            );

            if (std.os.linux.IN.DELETE_SELF == evt.mask) {
                const kv = filemap.fetchRemove(evt.wd) orelse unreachable;

                const watchfile = kv.value;
                print("=> {s}", .{watchfile.filename});

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

        if (should_run_command) {
            runCommand(args, gpa);
        }
    }
}

var running_pid: ?u32 = null;

pub fn setForeground(
    fd: c_int,
    pgrp: cc.pid_t,
) void {
    if (cc.tcsetpgrp(fd, pgrp) == -1) {
        panic("tcsetpgrp({}) => {}", .{ fd, errno() });
    }
}

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

    if (running_pid) |pid_| {
        const pid: cc.pid_t = @intCast(pid_);
        running_pid = null;

        { // kill
            if (cc.kill(pid, cc.SIGTERM) == -1) {
                log.debug("kill({}) => {} {s}", .{ -pid, errno(), errnoToString(errno()) });
                panic("kill({}) => {} {s}", .{ -pid, errno(), errnoToString(errno()) });
            }

            var wstatus: c_int = undefined;
            if (cc.waitpid(pid, &wstatus, 0) == -1) {
                panic("waitpid({}) => {} {s}", .{
                    pid,
                    errno(),
                    errnoToString(errno()),
                });
            }

            // if (cc.WIFEXITED(wstatus)) {
            //
            // }
            if (cc.WIFSIGNALED(wstatus)) {
                // if (cc.WTERMSIG(wstatus) != cc.SIGKILL) {
                //     log.err("[error]unexpectedly killed by signal => {}", .{cc.WTERMSIG(wstatus)});
                //     panic("[error]unexpectedly killed by signal => {}", .{cc.WTERMSIG(wstatus)});
                // }
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
            log.err("sigprocmask", .{});
            exit(1);
        }
    }

    const value = fork() catch {
        log.err("unexpeced error executing command", .{});
        exit(1);
    };

    switch (value) {
        .parent => |pid| {
            running_pid = @intCast(pid);

            if (cc.setpgid(pid, pid) == -1) {
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
                if (cc.setpgid(0, 0) == -1) {
                    panic(
                        "setpgid({}) => {} {s} ",
                        .{
                            cc.getpid(),
                            errno(),
                            errnoToString(errno()),
                        },
                    );
                }

                setForeground(tty.handle, cc.getpid());
            }

            defaultSignal(cc.SIGINT) catch panic("failed to reset signal", .{});
            defaultSignal(cc.SIGQUIT) catch panic("failed to reset signal", .{});
            defaultSignal(cc.SIGTSTP) catch panic("failed to reset signal", .{});
            defaultSignal(cc.SIGTTIN) catch panic("failed to reset signal", .{});
            defaultSignal(cc.SIGTTOU) catch panic("failed to reset signal", .{});
            defaultSignal(cc.SIGCHLD) catch panic("failed to reset signal", .{});

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
                _ = cc.execvp(cmd_name.ptr, @ptrCast(cmd_args.items.ptr));
                switch (errno()) {
                    cc.ENOENT => log.err(
                        "[error] pathname '{s}' does not exist.",
                        .{cmd_name},
                    ),
                    else => log.err(
                        "[error] failed to run executable => {}",
                        .{errno()},
                    ),
                }
                log.debug(
                    "execvp({s}) = {s}({})",
                    .{ cmd_name, errnoToString(errno()), errno() },
                );
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
