// TODO: CONFIG.timeout // timeout for cmd
// TODO: CONFIG.wait    // wait for cmd to finish before rerunnig

const std = @import("std");
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
const event_name_slack = std.fs.max_path_bytes;

const c = @import("c.zig");

pub const std_options: std.Options = .{
    .logFn = logFn,
};

const usage = "Usage: wfile <files> ... -c <command> ...";

const escape_codes = struct {
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
    const level_txt = switch (message_level) {
        .info => "",
        else => comptime message_level.asText() ++ ": ",
    };

    const prefix2 = if (scope == .default) "" else "(" ++ @tagName(scope) ++ "): ";
    const stderr = std.io.getStdErr().writer();
    var bw = std.io.bufferedWriter(stderr);
    const writer = bw.writer();
    const color = switch (message_level) {
        .info => "",
        .err => escape_codes.red,
        .warn => escape_codes.yellow,
        .debug => escape_codes.dim,
    };

    std.debug.lockStdErr();
    defer std.debug.unlockStdErr();
    nosuspend {
        writer.print(color ++ level_txt ++ prefix2 ++ format ++ "\n" ++ escape_codes.reset, args) catch return;
        bw.flush() catch return;
    }
}

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
        return debug.panic(
            "sigemptyset() => errno: {}",
            .{errno()},
        );
    }

    if (c.sigaddset(&signal_set, signal) == -1) {
        debug.panic("sigaddset() => errno: {}", .{errno()});
    }

    const act = c.struct_sigaction{
        .__sigaction_handler = .{ .sa_handler = c.SIG_IGN },
        .sa_mask = signal_set,
        .sa_flags = 0,
    };

    if (c.sigaction(signal, &act, null) == -1) {
        debug.panic("sigaction() => errno: {}", .{errno()});
    }
}

fn defaultSignal(signal: c_int) void {
    var signal_set: c.sigset_t = undefined;
    if (c.sigemptyset(&signal_set) == -1) {
        debug.panic("sigemptyset() = {}", .{errno()});
    }

    if (c.sigaddset(&signal_set, signal) == -1) {
        debug.panic("sigaddset() = {}", .{errno()});
    }

    const act = c.struct_sigaction{
        .__sigaction_handler = .{ .sa_handler = c.SIG_DFL },
        .sa_mask = signal_set,
        .sa_flags = 0,
    };

    if (c.sigaction(signal, &act, null) == -1) {
        debug.panic("sigaction({}, {}) = {}", .{ signal, act.sa_flags, errno() });
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
        return debug.panic(
            "failed to set filled signal set => {}",
            .{errno()},
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

fn sigChildHandler(
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
            debug.panic("unexpected child signal pid => {}", .{sigchld_pid});
        }

        var wstatus: c_int = undefined;

        if (c.waitpid(pid, &wstatus, 0) == -1) { // FIX:
            log.err("unexpected error", .{});
            debug.panic(
                "[signal] waitpid({}) = {}",
                .{ pid, errno() },
            );
            process.exit(1);
        }

        if (c.WIFEXITED(wstatus)) {
            const exit_status = c.WEXITSTATUS(wstatus);
            if (exit_status == 0)
                log.info("{s}  Exit Code: {}{s}", .{
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

const config = struct {
    pub var clear: ?u64 = std.time.ns_per_ms * 200;
    pub var recursive: bool = true;
    pub var include_exts: ?[]const []const u8 = null;
    pub var delay: u64 = std.time.ns_per_ms * 350;
};

const FileMap = std.AutoArrayHashMap(
    c_int,
    WatchDir,
);

pub var inotify_fd: i32 = undefined;

pub fn main() !void {
    { // globals

        GPA.requested_memory_limit = 50 * 1024;

        tty = fs.openFileAbsolute("/dev/tty", .{}) catch |err| {
            log.err("failed to open /dev/tty", .{});
            debug.panic("open /dev/tty = {s}", .{@errorName(err)});
        };

        stdout = io.getStdOut();
    }

    { // sig handler
        var block_chld = c.sigset_t{};
        if (c.sigemptyset(&block_chld) == -1) {
            debug.panic(
                "sigemptyset() = {}",
                .{errno()},
            );
        }

        if (c.sigaddset(&block_chld, c.SIGCHLD) == -1) {
            debug.panic(
                "sigaddset() = {}",
                .{errno()},
            );
        }

        var action = c.struct_sigaction{
            .__sigaction_handler = .{
                .sa_sigaction = sigChildHandler,
            },
            .sa_mask = block_chld,
            .sa_flags = c.SA_SIGINFO,
        };

        if (c.sigaction(c.SIGCHLD, &action, null) != 0) {
            debug.panic(
                "[error]sigaction() = {}",
                .{errno()},
            );
        }
    }

    createConfigFromArgs();

    const filelist: []const []const u8, const cmd_string: []const []const u8 = args: {
        var raw_args = process.args();
        assert(raw_args.skip());

        var file_args = std.ArrayList([]const u8).init(gpa);

        while (raw_args.next()) |arg| {
            if (mem.startsWith(u8, arg, "-c") or mem.startsWith(u8, arg, "--command"))
                break;

            if (mem.eql(u8, arg, "--exts")) {
                _ = raw_args.next().?;
                continue;
            }

            if (mem.startsWith(u8, arg, "-"))
                continue;

            file_args.append(arg) catch unreachable;
        }

        const has_dot_wfile: ?std.fs.File = std.fs.cwd().openFile("./.wfile", .{ .mode = .read_only }) catch null;
        if (has_dot_wfile) |dot_wfile| {
            const reader = dot_wfile.reader();
            defer dot_wfile.close();

            while (reader.readUntilDelimiterOrEofAlloc(gpa, '\n', std.fs.max_path_bytes) catch unreachable) |line| {
                const filepath = gpa.dupe(u8, line) catch unreachable;
                file_args.append(filepath) catch unreachable;
                std.log.debug(".wfile: {s}", .{line});
            }
        }

        var cmdlist = std.ArrayList([]const u8).init(gpa);
        while (raw_args.next()) |arg| {
            cmdlist.append(arg) catch unreachable;
        }

        const cmd_string = cmdlist.items;
        const filelist = file_args.items;

        log.debug("FileList: {s}\n", .{filelist});
        log.debug("CmdString: {s}\n", .{cmd_string});

        if (cmd_string.len == 0) {
            log.err("cmd string required", .{});
            log.info("{s}", .{usage});
            process.exit(1);
        }

        break :args .{ filelist, cmd_string };
    };

    const notify_flags = std.os.linux.IN.CLOEXEC;

    inotify_fd = std.posix.inotify_init1(notify_flags) catch |err|
        switch (err) {
        error.ProcessFdQuotaExceeded => debug.panic(
            "error: Process Quota reached --> Too many files to watch",
            .{},
        ),
        error.SystemFdQuotaExceeded => {
            debug.panic(
                "error: Process Quota reached --> Too many files to watch",
                .{},
            );
        },
        error.SystemResources => {
            log.err("unavailable resources", .{}); // TODO:
            process.exit(1);
        },
        else => {
            debug.panic("unexpected error: {s}", .{@errorName(err)});
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
                std.log.debug("add_dir: {s}", .{filename});
                _ = addDir(&filemap, gpa.dupe(u8, filename) catch unreachable);

                const directory = std.fs.cwd().openDir(filename, .{ .iterate = true, .no_follow = true }) catch unreachable;
                if (config.recursive) {
                    var walker = directory.walk(gpa) catch unreachable;
                    defer walker.deinit();

                    while (walker.next() catch unreachable) |entry| {
                        if (entry.kind == .directory) {
                            const dupe = std.fs.path.join(gpa, &.{ filename, entry.path }) catch unreachable;
                            std.log.debug("dir: {s}", .{dupe});

                            if (entry.kind == .directory) {
                                _ = addDir(&filemap, dupe);
                            }
                        }
                    }
                }
            },
            .file => {
                const dirname = std.fs.path.dirname(filename) orelse "./";
                std.log.debug("add_file: {s} dirname: {s} ", .{ filename, dirname });
                const basename = gpa.dupe(u8, std.fs.path.basename(filename)) catch unreachable;
                _ = addFile(&filemap, dirname, basename);
            },
            else => {
                log.warn("skipping file type: {s}", .{@tagName(stat.kind)});
            },
        }
    }
    if (filemap.count() == 0) {
        log.err("***no files to watch***", .{});
        log.info("{s}", .{usage});
        process.exit(1);
    }

    log.info("Watching {} directories", .{filemap.count()});

    for (filemap.values()) |wd| {
        if (wd.watched_files.items.len == 0) {
            log.info("> " ++ green("{s}"), .{wd.dirname}); // FIX: last slash
        } else {
            log.info("> " ++ green("{s}"), .{wd.dirname});
            for (wd.watched_files.items) |file| {
                log.info(green("    {s}"), .{file});
            }
        }
    }
    if (config.include_exts) |exts| {
        log.info("Extensions: {s}", .{exts});
    }

    const thread = try std.Thread.spawn(.{}, rerunProcess, .{cmd_string});
    defer thread.join();

    listen(gpa, inotify_fd, &filemap);
}

var should_restart_lock = std.Thread.Mutex{};
var should_restart = false;

/// continuosly run cmd_string
fn rerunProcess(args: []const []const u8) void {
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
            startProcess(args) catch debug.panic("unexpected error", .{});
        }

        time.sleep(config.delay);
    }
}

const WatchDir = struct {
    /// directory being watched
    dirname: []const u8,
    /// list of files to watch in this directory
    /// if `watch_files` is empty trigger on file change
    /// otherwise trigger only when file in this list is modified
    watched_files: std.ArrayList([]const u8),
    /// use same notify mask to watch a newly added child directory
    mask: u32,
};

const num_events_max = 1;
const event_size = @sizeOf(std.os.linux.inotify_event);
pub fn green(comptime str: []const u8) []const u8 {
    return "\u{1b}[38;5;2m" ++ str ++ "\u{1b}[m";
}

/// listen for file changes
fn listen(
    allocator: std.mem.Allocator,
    fd: c_int,
    filemap: *FileMap,
) void {
    const event_buffer = gpa.alloc(
        u8,
        (num_events_max * (event_size + event_name_slack)),
    ) catch unreachable; // FIX: read has variable bytes

    var log_filename_buffer: [1000]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&log_filename_buffer);
    var log_filename_arena = std.heap.ArenaAllocator.init(fba.allocator());

    while (true) {
        _ = log_filename_arena.reset(.retain_capacity);
        var log_filenames = std.ArrayList([]const u8).init(log_filename_arena.allocator());

        defer {
            log.info("Update:", .{});
            for (log_filenames.items) |name| {
                log.info("=> " ++ green("{s:>20}"), .{name});
            }
            log_filenames.clearAndFree();
        }

        defer {
            should_restart_lock.lock();
            if (should_restart) { //  waht??
                should_restart = true;
            }
            should_restart_lock.unlock();
        }

        const size = std.posix.read(fd, event_buffer) catch |err|
            switch (err) {
            error.WouldBlock => {
                log.err("unexpected non-blocking on file descriptor", .{});
                process.exit(1);
            },
            else => {
                log.err(
                    "unexpected error reading watched event = {s}",
                    .{@errorName(err)},
                );
                process.exit(1);
            },
        };
        debug.assert(size < event_buffer.len);

        var read_events_buf: []const u8 = event_buffer[0..size];
        read_events_buf = read_events_buf;

        while (read_events_buf.len > 0) {
            {
                // FIX: fix editors that create a backup delete, delete the original file then recreated
                time.sleep(time.ns_per_ms * 50);
            }
            const evt: *const std.os.linux.inotify_event =
                @ptrFromInt(@intFromPtr(read_events_buf.ptr));
            defer read_events_buf = read_events_buf[event_size + evt.len ..];

            formatEvent(evt);

            if (std.os.linux.IN.DELETE_SELF & evt.mask != 0) {
                const kv = filemap.fetchSwapRemove(evt.wd) orelse unreachable;
                log.err("=> Deleted: {s}", .{kv.value.dirname});
                gpa.free(kv.value.dirname);
            }

            if (std.os.linux.IN.CREATE & evt.mask != 0) {
                const name = evt.getName().?;
                const dir = filemap.get(evt.wd).?.dirname;
                const filename = std.fs.path.join(allocator, &.{ dir, name }) catch unreachable;

                const is_dir = (evt.mask & std.os.linux.IN.ISDIR) != 0;

                if (is_dir) {
                    if (addDir(filemap, filename)) {
                        log.info(escape_codes.green ++ "created {s}" ++ escape_codes.reset, .{filename});
                    }
                }
            }

            if (evt.getName()) |name| {
                const exists = for (log_filenames.items) |fname| {
                    if (std.mem.eql(u8, fname, name)) break true;
                } else false;

                if (!exists) log_filenames.append(name) catch unreachable;
            }

            should_restart = should_restart or shouldTriggerRestart(filemap, evt);
        }
    }
}

pub fn shouldTriggerRestart(filemap: *FileMap, evt: *const std.os.linux.inotify_event) bool {
    if (std.os.linux.IN.CREATE & evt.mask != 0 or
        std.os.linux.IN.MOVE & evt.mask != 0 or
        std.os.linux.IN.MODIFY & evt.mask != 0)
    {
        std.log.info("modified or created", .{});
        const watchdir = filemap.get(evt.wd).?;

        const dir_is_watching_file =
            watchdir.watched_files.items.len == 0 or
            blk: for (watchdir.watched_files.items) |item|
        {
            std.log.info("dir is watching", .{});
            const triggered_filename = evt.getName().?;
            if (std.mem.eql(u8, item, triggered_filename)) {
                break :blk true;
            }
        } else false;

        if (dir_is_watching_file) {
            return if (config.include_exts) |exts|
                (evt.mask & std.os.linux.IN.ISDIR == 0) and
                    isExtAllowed(exts, evt.getName().?)
            else
                true;
        }
    }

    if (std.os.linux.IN.MOVE_SELF & evt.mask != 0) {
        return true;
    }

    return false;
}

var running_pid: ?u32 = null;

pub fn setForeground(
    fd: c_int,
    pgrp: c.pid_t,
) void {
    ignoreSignal(c.SIGTTOU);
    defer defaultSignal(c.SIGTTOU);

    if (c.tcsetpgrp(fd, pgrp) == -1) {
        debug.panic("tcsetpgrp({}) = {}", .{ fd, errno() });
    }
}

pub fn stopRunningProcess() void {
    const saved = blk: { // block

        var blocked = c.sigset_t{};
        if (c.sigemptyset(&blocked) != 0) {
            debug.panic("sigemptyset", .{});
            process.exit(1);
        }
        if (c.sigaddset(&blocked, c.SIGCHLD) != 0) {
            debug.panic("sigaddset", .{});
            process.exit(1);
        }

        var saved_ = c.sigset_t{};
        if (c.sigprocmask(
            c.SIG_BLOCK,
            &blocked,
            &saved_,
        ) != 0) {
            log.err("failed to block signal", .{});
            debug.panic(
                "sigprocmask() = {}",
                .{errno()},
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
                debug.panic("killpg({}) = {}", .{ pgrp, errno() });
            }

            var wstatus: c_int = undefined;
            if (c.waitpid(pgrp, &wstatus, 0) == -1) {
                debug.panic("waitpid({}) = {}", .{
                    pgrp,
                    errno(),
                });
            }

            // if (cc.WIFEXITED(wstatus)) {
            //
            // }
            if (c.WIFSIGNALED(wstatus)) {
                // if (cc.WTERMSIG(wstatus) != cc.SIGKILL) {
                //     log.err("[error]unexpectedly killed by signal = {}", .{cc.WTERMSIG(wstatus)});
                //     debug.panic("[error]unexpectedly killed by signal = {}", .{cc.WTERMSIG(wstatus)});
                // }
            } else if (c.WIFSTOPPED(wstatus)) {
                debug.panic("unexpected caught signal; process stopped {}", .{pgrp});
            } else if (c.WIFCONTINUED(wstatus)) {
                debug.panic("unexpected caught signal; process continued {}", .{pgrp});
            }
        }
    }

    { // unblock

        if (c.sigprocmask(c.SIG_SETMASK, &saved, null) !=
            0)
        {
            debug.panic(
                "sigprocmask() = {}",
                .{errno()},
            );
        }
    }
}

fn blockSignal(sig: c_int) c.sigset_t {
    var mask = c.sigset_t{};
    var original: c.sigset_t = undefined;

    if (c.sigemptyset(&mask) != 0) {
        log.debug(
            "sigemptyset() = {}",
            .{errno()},
        );
        process.exit(1);
    }

    if (c.sigaddset(&mask, sig) != 0) {
        log.debug(
            "sigaddset() = {}",
            .{errno()},
        );
        process.exit(1);
    }

    if (c.sigprocmask(c.SIG_BLOCK, &mask, &original) != 0) {
        log.debug(
            "sigprocmask() = {}",
            .{errno()},
        );
        process.exit(1);
    }

    return original;
}

pub fn startProcess(
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
                    debug.panic(
                        "setpgid({},{}) => ",
                        .{ pid, errno() },
                    );
                }
                setForeground(tty.handle, pid);
            }

            if (c.kill(pid, c.SIGUSR2) != 0) {
                log.debug("kill() = {}", .{errno()});
                return error.UnexpectedError;
            }
        },
        .child => {
            { //
                if (c.setpgid(0, 0) == -1) {
                    log.debug(
                        "setpgid({}) = {}",
                        .{
                            c.getpid(),
                            errno(),
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
                    debug.panic("sigfillset = {}", .{errno()});
                }
                if (c.sigdelset(&mask, c.SIGUSR2) != 0) {
                    debug.panic("sigdelset = {}", .{errno()});
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

            if (config.clear) |delay| {
                clearScreen();
                time.sleep(delay);
            }

            _ = c.execvp(cmd_name.ptr, @ptrCast(cmd_args.items.ptr));
            const e = errno();

            switch (e) {
                c.ENOENT => log.warn(
                    "skipping '{s}', file does not exist.",
                    .{cmd_name},
                ),
                else => debug.panic(
                    "failed to run executable = {}",
                    .{e},
                ),
            }
            process.exit(1);
        },
    }

    if (c.sigprocmask(c.SIG_SETMASK, &restore_mask, null) != 0) {
        log.err("sigprocmask = {}", .{errno()});
        return error.UnexpectedError;
    }
}

///
fn clearScreen() void {
    io.getStdOut().writeAll("\u{1b}[2J\u{1b}[H") catch |err| {
        debug.panic("unable to write to standard output {s}", .{
            @errorName(err),
        });
    };
}

// ///
// fn eraseLine() void {
//     io.getStdOut().writeAll("\u{1b}[1K\u{0D}") catch |err|
//         debug.panic("unable to write to standard output {s}", .{@errorName(err)});
// }

/// set CONFIG variables
pub fn createConfigFromArgs() void {
    var args = process.args();
    while (args.next()) |arg| {
        if (mem.eql(u8, arg, "--delay")) {
            const delay_val = args.next() orelse @panic("--delay requires value");
            config.delay = std.fmt.parseInt(u32, delay_val, 10) catch @panic("invalid argument value");
        } else if (mem.eql(u8, arg, "--no-clear")) {
            config.clear = null;
        } else if (mem.eql(u8, arg, "--exts")) {
            const include_exts = args.next().?;
            std.log.debug("next: {s}", .{include_exts});
            var exts = std.ArrayList([]const u8).init(gpa);
            var split = std.mem.splitScalar(u8, include_exts, ',');
            while (split.next()) |ext| {
                exts.append(ext) catch unreachable;
            }
            config.include_exts = exts.items;
        } else if (mem.eql(u8, arg, "-r") or mem.eql(u8, arg, "--recursive")) {
            config.recursive = true;
        }
    }
}

pub fn formatEvent(event: *const std.os.linux.inotify_event) void {
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

pub fn addDir(filemap: *FileMap, dirname: []const u8) bool {
    log.debug("Watching directory => {s:>20}", .{dirname});

    const mask = (0 |
        std.os.linux.IN.IGNORED | // watch was removed
        std.os.linux.IN.MODIFY |
        std.os.linux.IN.CREATE |
        std.os.linux.IN.DELETE_SELF |
        std.os.linux.IN.DELETE |
        std.os.linux.IN.MOVE_SELF |
        std.os.linux.IN.MOVED_FROM |
        std.os.linux.IN.MOVED_TO);

    const wd = std.posix.inotify_add_watch(inotify_fd, dirname, mask) catch |err|
        switch (err) {
        error.AccessDenied => {
            log.err(
                "'{s}' Permission denied ",
                .{dirname},
            );
            return false;
        },
        error.FileNotFound => {
            log.warn(
                "'{s}' does not exist",
                .{dirname},
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
    if (entry.found_existing) return true;

    entry.value_ptr.* = WatchDir{
        .dirname = dirname,
        .watched_files = std.ArrayList([]const u8).init(filemap.allocator),
        .mask = mask,
    };

    return true;
}

pub fn addFile(filemap: *FileMap, dirname: []const u8, filename: []const u8) bool {
    log.debug("Watching file => {s:>20}", .{filename});
    const mask = (0 |
        std.os.linux.IN.IGNORED | // watch was removed
        std.os.linux.IN.MODIFY |
        std.os.linux.IN.CREATE |
        std.os.linux.IN.DELETE_SELF | //
        // std.os.linux.IN.DELETE | // file/dir inside watched dir was deleted
        std.os.linux.IN.MOVE_SELF | // watched file/dir moved
        std.os.linux.IN.MOVED_FROM | //
        std.os.linux.IN.MOVED_TO); //

    const wd = std.posix.inotify_add_watch(inotify_fd, dirname, mask) catch |err|
        switch (err) {
        error.AccessDenied => {
            log.err(
                "'{s}' Permission denied ",
                .{dirname},
            );
            return false;
        },
        error.FileNotFound => {
            log.warn(
                "'{s}' does not exist",
                .{dirname},
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
    if (!entry.found_existing) {
        entry.value_ptr.* = WatchDir{
            .dirname = dirname,
            .watched_files = std.ArrayList([]const u8).init(filemap.allocator),
            .mask = mask,
        };
    }

    const files = &entry.value_ptr.*.watched_files;
    files.append(filename) catch unreachable;

    return true;
}

pub fn isExtAllowed(extensions: []const []const u8, file: []const u8) bool {
    const ext = std.fs.path.extension(file)[1..];

    for (extensions) |e| {
        log.debug("ext: {s} {s} {s}", .{ e, ext, file });
        if (std.mem.eql(u8, e, ext)) return true;
    }

    return false;
}
