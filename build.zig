// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Spice parallelism option
    const enable_spice = b.option(bool, "spice", "Enable spice-based parallelism") orelse true;

    // Build options module
    const build_options = b.addOptions();
    build_options.addOption(bool, "enable_spice", enable_spice);

    // Get spice dependency if enabled
    const spice_mod: ?*std.Build.Module = if (enable_spice) blk: {
        const spice_dep = b.dependency("spice", .{
            .target = target,
            .optimize = optimize,
        });
        break :blk spice_dep.module("spice");
    } else null;

    // Get dependencies (optional for parent builds to disable)
    const use_json = b.option(bool, "json", "Use internal json dependency") orelse true;
    const use_yaml = b.option(bool, "yaml", "Use internal yaml dependency") orelse true;
    const use_toml = b.option(bool, "toml", "Use internal toml dependency") orelse true;

    const yaml_mod: ?*std.Build.Module = if (use_yaml) blk: {
        const yaml_dep = b.dependency("yaml", .{
            .target = target,
            .optimize = optimize,
            .spice = false,
        });
        break :blk yaml_dep.module("yaml");
    } else null;

    const toml_mod: ?*std.Build.Module = if (use_toml) blk: {
        const toml_dep = b.dependency("toml", .{
            .target = target,
            .optimize = optimize,
            .spice = false,
        });
        break :blk toml_dep.module("toml");
    } else null;

    const json_mod: ?*std.Build.Module = if (use_json) blk: {
        const json_dep = b.dependency("json", .{
            .target = target,
            .optimize = optimize,
            .spice = false,
        });
        break :blk json_dep.module("json");
    } else null;

    // Parallel module
    const parallel_mod = b.addModule("parallel", .{
        .root_source_file = b.path("src/parallel.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "build_options", .module = build_options.createModule() },
        },
    });
    if (spice_mod) |sm| {
        parallel_mod.addImport("spice", sm);
    }

    // Library module (for use as dependency)
    const config_mod = b.addModule("config", .{
        .root_source_file = b.path("src/config.zig"),
        .target = target,
        .optimize = optimize,
    });
    if (yaml_mod) |m| config_mod.addImport("yaml", m);
    if (toml_mod) |m| config_mod.addImport("toml", m);
    if (json_mod) |m| config_mod.addImport("json", m);
    config_mod.addImport("parallel", parallel_mod);

    // Static library
    const lib = b.addLibrary(.{
        .name = "zigconfig",
        .linkage = .static,
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/config.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    if (yaml_mod) |m| lib.root_module.addImport("yaml", m);
    if (toml_mod) |m| lib.root_module.addImport("toml", m);
    if (json_mod) |m| lib.root_module.addImport("json", m);
    b.installArtifact(lib);

    // Unit tests (tests in src/config.zig)
    const unit_tests_mod = b.createModule(.{
        .root_source_file = b.path("src/config.zig"),
        .target = target,
        .optimize = optimize,
    });
    if (yaml_mod) |m| unit_tests_mod.addImport("yaml", m);
    if (toml_mod) |m| unit_tests_mod.addImport("toml", m);
    if (json_mod) |m| unit_tests_mod.addImport("json", m);
    const unit_tests = b.addTest(.{
        .root_module = unit_tests_mod,
    });

    const run_unit_tests = b.addRunArtifact(unit_tests);

    // Integration tests (fixtures in test/fixtures)
    const integration_tests_mod = b.createModule(.{
        .root_source_file = b.path("src/integration_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    if (yaml_mod) |m| integration_tests_mod.addImport("yaml", m);
    if (toml_mod) |m| integration_tests_mod.addImport("toml", m);
    if (json_mod) |m| integration_tests_mod.addImport("json", m);
    const integration_tests = b.addTest(.{
        .root_module = integration_tests_mod,
    });
    const run_integration_tests = b.addRunArtifact(integration_tests);

    // Test step runs unit tests
    const test_step = b.step("test", "Run all tests");
    test_step.dependOn(&run_unit_tests.step);
    test_step.dependOn(&run_integration_tests.step);

    // Separate step for just unit tests
    const unit_test_step = b.step("test-unit", "Run unit tests");
    unit_test_step.dependOn(&run_unit_tests.step);

    const integration_test_step = b.step("test-integration", "Run integration tests");
    integration_test_step.dependOn(&run_integration_tests.step);

    // Check step (compile without running)
    const check_mod = b.createModule(.{
        .root_source_file = b.path("src/config.zig"),
        .target = target,
        .optimize = optimize,
    });
    if (yaml_mod) |m| check_mod.addImport("yaml", m);
    if (toml_mod) |m| check_mod.addImport("toml", m);
    if (json_mod) |m| check_mod.addImport("json", m);
    const check = b.addTest(.{
        .root_module = check_mod,
    });
    const check_step = b.step("check", "Check for compilation errors");
    check_step.dependOn(&check.step);

    // Documentation generation
    const docs_mod = b.createModule(.{
        .root_source_file = b.path("src/config.zig"),
        .target = target,
        .optimize = .Debug,
    });
    if (yaml_mod) |m| docs_mod.addImport("yaml", m);
    if (toml_mod) |m| docs_mod.addImport("toml", m);
    if (json_mod) |m| docs_mod.addImport("json", m);
    const docs = b.addObject(.{
        .name = "zigconfig",
        .root_module = docs_mod,
    });
    const install_docs = b.addInstallDirectory(.{
        .source_dir = docs.getEmittedDocs(),
        .install_dir = .prefix,
        .install_subdir = "docs",
    });
    const docs_step = b.step("docs", "Generate API documentation");
    docs_step.dependOn(&install_docs.step);

    // Benchmark executable (ReleaseFast for realistic timings)
    const bench_exe = b.addExecutable(.{
        .name = "bench",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/bench.zig"),
            .target = target,
            .optimize = .ReleaseFast,
            .imports = &.{
                .{ .name = "config", .module = config_mod },
            },
        }),
    });
    const bench_step = b.step("bench", "Run benchmarks");
    bench_step.dependOn(&b.addRunArtifact(bench_exe).step);

    // Examples
    const examples = .{
        .{ "basic_parsing", "Basic configuration parsing example" },
        .{ "typed_loader", "Type-safe loader example" },
        .{ "flag_parsing", "Command-line flag parsing example" },
        .{ "secret_handling", "Secure secret handling example" },
        .{ "validation", "Configuration validation example" },
        .{ "xdg_paths", "XDG directory paths example" },
        .{ "dotenv_loading", "Dotenv file loading example" },
    };

    const examples_step = b.step("examples", "Build all examples");

    inline for (examples) |example| {
        const exe = b.addExecutable(.{
            .name = "example-" ++ example[0],
            .root_module = b.createModule(.{
                .root_source_file = b.path("examples/" ++ example[0] ++ ".zig"),
                .target = target,
                .optimize = optimize,
                .imports = &.{
                    .{ .name = "config", .module = config_mod },
                },
            }),
        });

        const install_exe = b.addInstallArtifact(exe, .{});
        const run_exe = b.addRunArtifact(exe);

        const run_step = b.step("run-" ++ example[0], "Run the " ++ example[1]);
        run_step.dependOn(&run_exe.step);

        examples_step.dependOn(&install_exe.step);
    }
}
