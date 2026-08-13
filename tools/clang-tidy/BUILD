load("@base_pip3//:requirements.bzl", "requirement")
load("@envoy_repo//:path.bzl", "PATH")
load("@rules_python//python:defs.bzl", "py_binary")
load(":clang_tidy.bzl", "clang_tidy")

licenses(["notice"])  # Apache 2

clang_tidy(
    name = "clang-tidy",
    # TODO: make this work with toolchain_roots
    target = "@llvm_toolchain_llvm//:clang-tidy",
)

clang_tidy(
    name = "clang-apply-replacements",
    binary_name = "clang-apply-replacements",
    # Unlike clang-tidy/clang-format, the LLVM distribution repo has no
    # convenience filegroup for clang-apply-replacements, so fish it out of the
    # `:bin` filegroup (a glob over bin/**) which is always present.
    # TODO: make this work with toolchain_roots
    target = "@llvm_toolchain_llvm//:bin",
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
