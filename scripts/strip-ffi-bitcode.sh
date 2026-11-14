#!/usr/bin/env bash
# Strip LLVM bitcode / LTO sections embedded by prebuilt Rust sysroot objects
# from static FFI archives (.a) so Go 1.27+ cgo linker security checks accept them.
#
# Note: on macOS (Mach-O), Apple's `strip -S` must NOT be used on Rust staticlibs
# because it strips `.llvm.<hash>` suffixes from `private external` symbols and
# triggers duplicate-symbol link errors. Use `llvm-objcopy` (from `rustup component
# add llvm-tools` or PATH) on Mach-O, and `llvm-objcopy` or GNU `objcopy` on
# ELF/COFF archives.
#
# Verification is strictly fail-closed: inspector output is captured completely
# to a temporary file before scanning (avoiding SIGPIPE false negatives under
# `pipefail`), and missing or failing section-inspection tools exit non-zero.
set -euo pipefail

if [ "$#" -eq 2 ] && [ "$1" = "--check" ]; then
    check_only=1
    archive="$2"
elif [ "$#" -eq 1 ] && [ "$1" != "--check" ]; then
    check_only=0
    archive="$1"
else
    echo "usage: $0 [--check] <path-to-libseclusor_ffi.a>" >&2
    exit 2
fi

if [ ! -f "$archive" ]; then
    echo "error: archive not found: $archive" >&2
    exit 1
fi

find_llvm_tool() {
    local tool="$1"
    if command -v rustc >/dev/null 2>&1; then
        local sysroot host candidate
        sysroot="$(rustc --print sysroot 2>/dev/null || true)"
        host="$(rustc -vV 2>/dev/null | sed -n 's/^host: //p')"
        if [ -n "$sysroot" ] && [ -n "$host" ]; then
            candidate="$sysroot/lib/rustlib/$host/bin/$tool"
            if [ -x "$candidate" ]; then
                echo "$candidate"
                return 0
            fi
            if [ -x "${candidate}.exe" ]; then
                echo "${candidate}.exe"
                return 0
            fi
        fi
    fi
    if command -v "$tool" >/dev/null 2>&1; then
        command -v "$tool"
        return 0
    fi
    return 1
}

llvm_objcopy="$(find_llvm_tool llvm-objcopy || true)"
llvm_objdump="$(find_llvm_tool llvm-objdump || true)"

tmp_hdr="$(mktemp "${TMPDIR:-/tmp}/strip-ffi-bitcode.XXXXXX")"
trap 'rm -f "$tmp_hdr"' EXIT

detect_archive_kind() {
    if [ -n "$llvm_objdump" ]; then
        "$llvm_objdump" -h "$archive" >"$tmp_hdr"
        if grep -qi 'file format mach-o' "$tmp_hdr"; then
            echo "macho"
            return 0
        fi
        if grep -Eqi 'file format (elf|coff|pe-)' "$tmp_hdr"; then
            echo "elf_or_coff"
            return 0
        fi
    elif [ "$(uname -s)" = "Darwin" ] && command -v otool >/dev/null 2>&1; then
        otool -hl "$archive" >"$tmp_hdr"
        if grep -q 'Mach header' "$tmp_hdr"; then
            echo "macho"
            return 0
        fi
    elif command -v objdump >/dev/null 2>&1; then
        objdump -h "$archive" >"$tmp_hdr"
        if grep -Eqi 'file format (elf|coff|pe-)' "$tmp_hdr"; then
            echo "elf_or_coff"
            return 0
        fi
    fi
    echo "error: unable to inspect archive format for $archive (install llvm-tools or binutils/otool)" >&2
    exit 1
}

kind="$(detect_archive_kind)"

case "$kind" in
macho)
    if [ "$check_only" -eq 0 ]; then
        if [ -z "$llvm_objcopy" ]; then
            echo "error: llvm-objcopy not found (run 'rustup component add llvm-tools')" >&2
            exit 1
        fi
        remove_args=(
            "--remove-section=__LLVM,__bitcode"
            "--remove-section=__LLVM,__cmdline"
        )
        if [ -n "$llvm_objdump" ]; then
            "$llvm_objdump" --macho --private-headers "$archive" >"$tmp_hdr"
        elif command -v otool >/dev/null 2>&1; then
            otool -hl "$archive" >"$tmp_hdr"
        else
            : >"$tmp_hdr"
        fi
        while IFS= read -r pair; do
            if [ -n "$pair" ] && [ "$pair" != "__LLVM,__bitcode" ] && [ "$pair" != "__LLVM,__cmdline" ]; then
                remove_args+=("--remove-section=$pair")
            fi
        done < <(awk '
            $1 == "sectname" { sect = $2 }
            $1 == "segname" && sect != "" {
                seg = $2
                if (seg == "__LLVM" || seg == "__GNU_LTO" || sect ~ /^(__bitcode|__cmdline|\.llvmbc|\.llvmcmd|\.llvm\.lto|\.gnu\.lto_|\.gnu\.debuglto_)/) {
                    print seg "," sect
                }
                sect = ""
            }
        ' "$tmp_hdr" | sort -u)
        "$llvm_objcopy" "${remove_args[@]}" "$archive"
    fi

    verified=0
    if command -v otool >/dev/null 2>&1; then
        otool -hl "$archive" >"$tmp_hdr"
        if grep -Eq 'segname (__LLVM|__GNU_LTO)|sectname (__bitcode|__cmdline|\.llvmbc|\.llvmcmd)' "$tmp_hdr"; then
            echo "error: disallowed Mach-O LTO/bitcode section remained in $archive after llvm-objcopy" >&2
            exit 1
        fi
        verified=1
    fi
    if [ -n "$llvm_objdump" ]; then
        "$llvm_objdump" --macho --private-headers "$archive" >"$tmp_hdr"
        if grep -Eq 'segname (__LLVM|__GNU_LTO)|sectname (__bitcode|__cmdline|\.llvmbc|\.llvmcmd)' "$tmp_hdr"; then
            echo "error: disallowed Mach-O LTO/bitcode segment/section remained in $archive" >&2
            exit 1
        fi
        "$llvm_objdump" -h "$archive" >"$tmp_hdr"
        if awk '$2 ~ /^(__bitcode|__cmdline|\.llvmbc|\.llvmcmd|\.llvm\.lto|\.gnu\.lto_|\.gnu\.debuglto_)/ { found=1 } END { exit !found }' "$tmp_hdr"; then
            echo "error: disallowed LTO/bitcode section remained in $archive after llvm-objcopy" >&2
            exit 1
        fi
        verified=1
    fi
    if [ "$verified" -ne 1 ]; then
        echo "error: no Mach-O verifier (otool or llvm-objdump) available for $archive" >&2
        exit 1
    fi
    ;;

elf_or_coff)
    if [ "$check_only" -eq 0 ]; then
        if [ -n "$llvm_objcopy" ] && [ -n "$llvm_objdump" ]; then
            "$llvm_objdump" -h "$archive" >"$tmp_hdr"
            remove_args=(
                "--remove-section=.llvmbc"
                "--remove-section=.llvmcmd"
            )
            while IFS= read -r sec; do
                if [ -n "$sec" ] && [ "$sec" != ".llvmbc" ] && [ "$sec" != ".llvmcmd" ]; then
                    remove_args+=("--remove-section=$sec")
                fi
            done < <(awk '$2 ~ /^(\.llvmbc|\.llvmcmd|\.llvm\.lto|\.gnu\.lto_|\.gnu\.debuglto_)/ { print $2 }' "$tmp_hdr" | sort -u)
            "$llvm_objcopy" "${remove_args[@]}" "$archive"
        elif command -v objcopy >/dev/null 2>&1; then
            objcopy \
                --wildcard \
                -R .llvmbc \
                -R .llvmcmd \
                -R '.llvm.lto*' \
                -R '.gnu.lto_*' \
                -R '.gnu.debuglto_*' \
                "$archive"
        else
            echo "error: neither llvm-objcopy+llvm-objdump nor GNU objcopy found for $archive" >&2
            exit 1
        fi
    fi

    if [ -n "$llvm_objdump" ]; then
        "$llvm_objdump" -h "$archive" >"$tmp_hdr"
    elif command -v objdump >/dev/null 2>&1; then
        objdump -h "$archive" >"$tmp_hdr"
    else
        echo "error: no ELF/COFF verifier (llvm-objdump or objdump) available for $archive" >&2
        exit 1
    fi

    if awk '$2 ~ /^(\.llvmbc|\.llvmcmd|\.llvm\.lto|\.gnu\.lto_|\.gnu\.debuglto_)/ { found=1 } END { exit !found }' "$tmp_hdr"; then
        echo "error: disallowed LTO/bitcode section remained in $archive after strip" >&2
        exit 1
    fi
    ;;
esac
