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

    // Get dependencies
    const yaml_dep = b.dependency("yaml", .{
        .target = target,
        .optimize = optimize,
    });
    const yaml_mod = yaml_dep.module("yaml");

    const toml_dep = b.dependency("toml", .{
        .target = target,
        .optimize = optimize,
    });
    const toml_mod = toml_dep.module("toml");

    const json_dep = b.dependency("json", .{
        .target = target,
        .optimize = optimize,
    });
    const json_mod = json_dep.module("json");

    // R-07: Define shared parser import list to avoid repetition across build targets
    const parser_imports: []const std.Build.Module.Import = &.{
        .{ .name = "yaml", .module = yaml_mod },
        .{ .name = "toml", .module = toml_mod },
        .{ .name = "json", .module = json_mod },
    };

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
        .imports = parser_imports,
    });
    config_mod.addImport("parallel", parallel_mod);

    // Static library
    const lib = b.addLibrary(.{
        .name = "zigconfig",
        .linkage = .static,
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/config.zig"),
            .target = target,
            .optimize = optimize,
            .imports = parser_imports,
        }),
    });
    b.installArtifact(lib);

    // Unit tests (tests in src/config.zig)
    const unit_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/config.zig"),
            .target = target,
            .optimize = optimize,
            .imports = parser_imports,
        }),
    });

    const run_unit_tests = b.addRunArtifact(unit_tests);

    // Integration tests (fixtures in test/fixtures)
    const integration_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/integration_test.zig"),
            .target = target,
            .optimize = optimize,
            .imports = parser_imports,
        }),
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
    const check = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/config.zig"),
            .target = target,
            .optimize = optimize,
            .imports = parser_imports,
        }),
    });
    const check_step = b.step("check", "Check for compilation errors");
    check_step.dependOn(&check.step);

    // Documentation generation
    const docs = b.addObject(.{
        .name = "zigconfig",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/config.zig"),
            .target = target,
            .optimize = .Debug,
            .imports = parser_imports,
        }),
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
