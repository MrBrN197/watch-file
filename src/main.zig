// TODO: CONFIG.timeout // timeout for cmd
// TODO: CONFIG.wait    // wait for cmd to finish before rerunnig

const std = @import("std");
const c = @import("./c.zig");

pub const std_options: std.Options = .{
    .logFn = logFn,
};

const EscapeCodes = struct {
    pub const dim = "\u{1b}[2m";
    pub const white = "\u{1b}[37m";
    pub const red = "\u{1b}[31m";
    pub const yellow = "\u{1b}[33m";
    pub const green = "\u{1b}[32m";
    pub const magenta = "\u{1b}[35m";
    pub const cyan = "\u{1b}[36m";
    pub const reset = "\u{1b}[0m";
};

fn logFn(
    comptime message_level: std.log.Level,
    comptime scope: @Type(.enum_literal),
    comptime format: []const u8,
    args: anytype,
) void {
    const level_txt = comptime message_level.asText();
    const prefix2 = if (scope == .default) ": " else "(" ++ @tagName(scope) ++ "): ";
    const stderr = std.io.getStdErr().writer();
    var bw = std.io.bufferedWriter(stderr);
    const writer = bw.writer();
    const color = switch (message_level) {
        .info => "",
        .err => EscapeCodes.red,
        .warn => EscapeCodes.yellow,
        .debug => EscapeCodes.dim,
    };

    std.debug.lockStdErr();
    defer std.debug.unlockStdErr();
    nosuspend {
        writer.print(color ++ level_txt ++ prefix2 ++ format ++ "\n" ++ EscapeCodes.reset, args) catch return;
        bw.flush() catch return;
    }
}

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
                log.info("{s}  Status: {}{s}", .{
                    "\u{1b}[38;5;2m",
                    exit_status,
                    "\u{1b}[m",
                })
            else
                log.info("{s} ❌Status: {}{s}", .{
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
    pub var recursive: bool = true;
    pub var include_exts: ?[]const []const u8 = null;
};

const FileMap = std.AutoHashMap(
    c_int,
    WatchFile,
);

pub var inotify_fd: i32 = undefined;

pub fn main() !void {
    { // globals

        // GPA.setRequestedMemoryLimit(
        //     50000,
        // );

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

    parse_config();

    const filelist: []const []const u8, const cmd_string: []const []const u8 = args: {
        var raw_args = process.args();
        assert(raw_args.skip());

        var arglist = std.ArrayList([]const u8).init(gpa);

        while (raw_args.next()) |arg| {
            if (mem.startsWith(u8, arg, "-c") or mem.startsWith(u8, arg, "--command"))
                break;
            if (mem.startsWith(u8, arg, "-"))
                continue;

            arglist.append(arg) catch unreachable;
        }

        var cmdlist = std.ArrayList([]const u8).init(gpa);
        while (raw_args.next()) |arg| {
            cmdlist.append(arg) catch unreachable;
        }

        // const command_start_idx = for (arglist.items, 0..) |arg, idx| {
        //     std.log.info("{s}", .{arg});
        //     if (eql(u8, arg, "-c")) break idx;
        // } else {
        //     log.err(
        //         \\command required
        //         \\Usage: watchfile <files...> -c <command...>
        //     , .{});
        //     exit(1);
        // };

        const cmd_string = cmdlist.items;
        const filelist = arglist.items;

        log.debug("FileList: {s}\n", .{filelist});
        log.debug("CmdString: {s}\n", .{cmd_string});

        if (filelist.len == 0 or cmd_string.len == 0) {
            log.err("files required", .{});
            log.info("Usage: wfile <files...> -c <command...>", .{});
            exit(1);
        }

        break :args .{ filelist, cmd_string };
    };

    const notify_flags = std.os.linux.IN.CLOEXEC;

    inotify_fd = std.posix.inotify_init1(notify_flags) catch |err|
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

    var filemap = FileMap.init(std.heap.page_allocator);

    for (filelist) |filename| {
        const stat = std.fs.cwd().statFile(filename) catch |err| switch (err) {
            else => {
                log.warn("unable to stat file {s} {s}", .{ filename, @errorName(err) });
                continue;
            },
        };

        std.log.debug("Filename: {s}", .{filename});
        switch (stat.kind) {
            .directory => {
                const watch_filename = gpa.dupe(u8, filename) catch unreachable;
                _ = add_file(&filemap, watch_filename);

                const directory = std.fs.cwd().openDir(filename, .{ .iterate = true, .no_follow = true }) catch unreachable;
                if (CONFIG.recursive) {
                    var walker = directory.walk(gpa) catch unreachable;
                    defer walker.deinit();

                    while (walker.next() catch unreachable) |entry| {
                        const dupe = std.fs.path.join(gpa, &.{ filename, entry.path }) catch unreachable;
                        std.log.debug("dir: {s}", .{dupe});

                        if (entry.kind == .directory) {
                            _ = add_file(&filemap, dupe);
                        }
                    }
                }
            },
            .file => {
                if (CONFIG.include_exts) |include_exts| {
                    if (include_extension(include_exts, filename)) {
                        const dupe = gpa.dupe(u8, filename) catch unreachable;
                        _ = add_file(&filemap, dupe);
                    }
                } else {
                    const dupe = gpa.dupe(u8, filename) catch unreachable;
                    _ = add_file(&filemap, dupe);
                }
            },
            else => {
                log.warn("skipping file type: {s}", .{@tagName(stat.kind)});
            },
        }
    }

    log.info("Watching {} files", .{filemap.count()});

    if (filemap.count() == 0) {
        log.err("***no files to watch***", .{});
        exit(1);
    }

    const thread = try std.Thread.spawn(.{}, rerun_cmd, .{cmd_string});
    defer thread.join();

    listen(gpa, inotify_fd, &filemap);
}

var should_restart_lock = std.Thread.Mutex{};
var should_restart = false;

const DELAY_MS = 350;

/// continuosly run cmd_string
fn rerun_cmd(args: []const []const u8) void {
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
            stop_running_process();
            start_process(args) catch panic("unexpected error", .{});
        }

        sleep(time.ns_per_ms * DELAY_MS);
    }
}

const WatchFile = struct {
    filename: []const u8,
    mask: u32,
};

const num_events_max = 1;
const event_size = @sizeOf(std.os.linux.inotify_event);
const event_name_slack = std.fs.max_path_bytes;

/// listen for file changes
fn listen(
    allocator: std.mem.Allocator,
    fd: c_int,
    filemap: *std.AutoHashMap(c_int, WatchFile),
) void {
    const buffer = std.heap.page_allocator.alloc(
        u8,
        (num_events_max * (event_size + event_name_slack)),
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
        debug.assert(size < buffer.len);

        var read_events_buf: []const u8 = buffer[0..size];
        read_events_buf = read_events_buf;

        while (read_events_buf.len > 0) {
            const evt: *const std.os.linux.inotify_event =
                @ptrFromInt(@intFromPtr(read_events_buf.ptr));
            defer read_events_buf = read_events_buf[event_size + evt.len ..];

            format_event(evt, filemap.*);

            if (std.os.linux.IN.MODIFY & evt.mask != 0 or
                std.os.linux.IN.CREATE & evt.mask != 0)
            {
                log.info("=> {s}", .{evt.getName().?});
            }

            if (std.os.linux.IN.DELETE_SELF & evt.mask != 0) {
                const kv = filemap.fetchRemove(evt.wd) orelse unreachable;
                gpa.free(kv.value.filename);
            }

            if (std.os.linux.IN.CREATE & evt.mask != 0) {
                const name = evt.getName().?;
                const dir = filemap.get(evt.wd).?.filename;
                const filename = std.fs.path.join(allocator, &.{ dir, name }) catch unreachable;

                const is_dir = evt.mask & std.os.linux.IN.ISDIR != 0;

                if (is_dir) {
                    if (add_file(filemap, filename)) {
                        log.info(EscapeCodes.green ++ "created {s}" ++ EscapeCodes.reset, .{filename});
                    }
                }
            }

            if (std.os.linux.IN.CREATE & evt.mask != 0 or
                std.os.linux.IN.MODIFY & evt.mask != 0)
            {
                should_restart = if (CONFIG.include_exts) |exts|
                    include_extension(exts, evt.getName().?)
                else
                    true;
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

pub fn stop_running_process() void {
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

pub fn start_process(
    args: []const []const u8,
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
                var buffer: [1000]u8 = undefined;
                var fba = std.heap.FixedBufferAllocator.init(&buffer);

                const allocator = fba.allocator();

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
                    "skipping '{s}', file does not exist.",
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

// ///
// fn eraseLine() void {
//     io.getStdOut().writeAll("\u{1b}[1K\u{0D}") catch |err|
//         panic("unable to write to standard output {s}", .{@errorName(err)});
// }

/// set CONFIG variables
pub fn parse_config() void {
    var args = process.args();
    while (args.next()) |arg| {
        if (mem.eql(u8, arg, "--clear")) {
            CONFIG.clear = true;
        } else if (mem.eql(u8, arg, "--exts")) {
            const include_exts = args.next().?;
            var exts = std.ArrayList([]const u8).init(gpa);
            var split = std.mem.splitScalar(u8, include_exts, ',');
            while (split.next()) |ext| {
                exts.append(ext) catch unreachable;
            }
            CONFIG.include_exts = exts.items;
        } else if (mem.eql(u8, arg, "-r") or mem.eql(u8, arg, "--recursive")) {
            CONFIG.recursive = true;
        }
    }
}

pub fn format_event(event: *const std.os.linux.inotify_event, filemap: FileMap) void {
    _ = filemap; // autofix
    if (event.mask == 0) return;

    log.debug(
        \\File: {?s} ({})
    , .{ event.getName(), event.wd });

    const event_struct: std.builtin.Type.Struct = @typeInfo(std.os.linux.IN).@"struct";
    const mask_declarations = event_struct.decls;

    // var buffer: [32]u8 = undefined;
    // @memset(&buffer, ' ');
    // inline for (0..32) |i| {
    //     if (@shlExact(1, i) & event.mask != 0) {
    //         buffer[i] = '|';
    //     }
    // }
    // std.log.info("buffer: {s}", .{buffer});

    inline for (mask_declarations) |decl| {
        const mask_value = @field(std.os.linux.IN, decl.name);
        if (std.mem.eql(u8, decl.name, "ALL_EVENTS")) {} else {
            if (mask_value & event.mask != 0) {
                log.debug(" Mask: {s:>10}: {b:>32}", .{ decl.name, mask_value });
            }
        }
    }
}

pub fn add_file(filemap: *FileMap, filename: []const u8) bool {
    const mask = (0 |
        std.os.linux.IN.IGNORED | // TODO: remove; handled by IN.DELETE_SELF
        std.os.linux.IN.MODIFY | // file inside watched dir was modified
        std.os.linux.IN.CREATE | // file/dir created in watched dir
        std.os.linux.IN.DELETE_SELF | // watched file/dir deleted
        std.os.linux.IN.DELETE | // file/dir inside watched dir was deleted
        std.os.linux.IN.MOVE_SELF | // watched file/dir moved
        std.os.linux.IN.MOVED_FROM | //
        std.os.linux.IN.MOVED_TO); //

    const wd = std.posix.inotify_add_watch(inotify_fd, filename, mask) catch |err|
        switch (err) {
        error.AccessDenied => {
            log.err(
                "'{s}' Permission denied ",
                .{filename},
            );
            return false;
        },
        error.FileNotFound => {
            log.warn(
                "'{s}' does not exist",
                .{filename},
            );
            return false;
        },
        else => {
            log.err(
                "unexpected error \nskipping {s}",
                .{@errorName(err)},
            );

            return false;
        },
    };

    const entry = filemap.getOrPut(wd) catch unreachable;

    if (entry.found_existing) return false;

    log.info("=> {s:>20} ({})", .{ filename, wd });

    entry.value_ptr.* = WatchFile{
        .filename = filename,
        .mask = mask,
    };

    return true;
}

pub fn include_extension(extensions: []const []const u8, file: []const u8) bool {
    const ext = std.fs.path.extension(file)[1..];

    for (extensions) |e| {
        log.debug("ext: {s} {s} {s}", .{ e, ext, file });
        if (std.mem.eql(u8, e, ext)) return true;
    }

    return false;
}
