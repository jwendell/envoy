load("@base_pip3//:requirements.bzl", "requirement")
load("@bazel_skylib//rules:native_binary.bzl", "native_binary")
load("@envoy_repo//:path.bzl", "PATH")
load("@rules_python//python:defs.bzl", "py_binary")

licenses(["notice"])  # Apache 2

# clang-tidy and clang-apply-replacements are self-contained binaries in the
# hermetic LLVM distribution (statically linked against LLVM; only need system
# libs, no sibling lib/ runfiles). The toolchain repo exposes them only as files
# (or single-file filegroups), not as runnable targets, so wrap them with
# native_binary so `bazel run` works. The binaries come from the hermetic
# toolchain, not the host.
native_binary(
    name = "clang-tidy",
    src = "@llvm_toolchain_llvm//:clang-tidy",
    out = "clang-tidy",
    visibility = ["//visibility:public"],
)

native_binary(
    name = "clang-apply-replacements",
    src = "@llvm_toolchain_llvm//:bin/clang-apply-replacements",
    out = "clang-apply-replacements",
    visibility = ["//visibility:public"],
)

py_binary(
    name = "collect_fixes",
    srcs = ["collect_fixes.py"],
    args = ["--workspace_root=%s" % PATH],
    main = "collect_fixes.py",
    visibility = ["//visibility:public"],
    deps = [requirement("pyyaml")],
)
