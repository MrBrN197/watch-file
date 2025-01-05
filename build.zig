const std = @import("std");

comptime { // version check
    const REQUIRED_VERSION_STR = "0.14.0-dev.109+b6fd34aa4";
    const builtin = @import("builtin");

    const required_version = std.SemanticVersion.parse(
        REQUIRED_VERSION_STR,
    ) catch unreachable;

    if (builtin.zig_version.order(required_version) == .lt) {
        @compileError(std.fmt.comptimePrint(
            \\
            \\ Required zig version >={s}
            \\ Current zig version: {s}
        , .{ REQUIRED_VERSION_STR, builtin.zig_version_string }));
    }

    if (builtin.os.tag != .linux) {
        @compileError("requires Linux");
    }
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe = b.addExecutable(.{
        .name = "wfile",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    exe.linkLibC();

    const use_llvm = if (b.option(bool, "use-llvm", "Use LLVM")) |value|
        value
    else
        optimize != .Debug;

    exe.use_llvm = use_llvm;
    exe.use_lld = use_llvm;

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);

    run_cmd.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);
}
