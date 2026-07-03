#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
    echo "usage: $0 <vscode|ida|ghidra|binja> [--ida-dir <path>] [--ghidra-scripts <path>] [--binja-plugins <path>]"
    echo
    echo "  vscode   install the VS Code extension to ~/.vscode/extensions/disrobe-vscode"
    echo "  ida      copy disrobe_ida.py to the IDA plugins directory"
    echo "  ghidra   copy DisrobeAnalyzer.java to the Ghidra scripts directory"
    echo "  binja    copy the binja plugin to the Binary Ninja user plugins directory"
    exit 1
}

if [ $# -lt 1 ]; then
    usage
fi

EDITOR="$1"
shift

IDA_DIR=""
GHIDRA_SCRIPTS=""
BINJA_PLUGINS=""

while [ $# -gt 0 ]; do
    case "$1" in
        --ida-dir)
            IDA_DIR="${2:-}"
            shift 2
            ;;
        --ghidra-scripts)
            GHIDRA_SCRIPTS="${2:-}"
            shift 2
            ;;
        --binja-plugins)
            BINJA_PLUGINS="${2:-}"
            shift 2
            ;;
        *)
            echo "unknown flag: $1" >&2
            usage
            ;;
    esac
done

install_vscode() {
    local target="${HOME}/.vscode/extensions/disrobe-vscode"
    echo "installing disrobe VS Code extension to ${target}"
    rm -rf "${target}"
    cp -r "${SCRIPT_DIR}/vscode" "${target}"
    echo "done: extension installed at ${target}"
    echo "reload VS Code or run 'code --install-extension ${target}' to activate"
}

install_ida() {
    if [ -z "${IDA_DIR}" ]; then
        if [ "$(uname)" = "Darwin" ]; then
            IDA_DIR="${HOME}/Library/Application Support/hex-rays/ida pro/plugins"
        else
            IDA_DIR="${HOME}/.idapro/plugins"
        fi
    fi
    local dst="${IDA_DIR}/disrobe_ida.py"
    echo "installing disrobe IDA plugin to ${dst}"
    mkdir -p "${IDA_DIR}"
    cp "${SCRIPT_DIR}/ida/disrobe_ida.py" "${dst}"
    echo "done: plugin copied to ${dst}"
    echo "restart IDA Pro to load the plugin"
}

install_ghidra() {
    if [ -z "${GHIDRA_SCRIPTS}" ]; then
        GHIDRA_SCRIPTS="${HOME}/ghidra_scripts"
    fi
    local dst="${GHIDRA_SCRIPTS}/DisrobeAnalyzer.java"
    echo "installing disrobe Ghidra script to ${dst}"
    mkdir -p "${GHIDRA_SCRIPTS}"
    cp "${SCRIPT_DIR}/ghidra/DisrobeAnalyzer.java" "${dst}"
    echo "done: script copied to ${dst}"
    echo "in Ghidra: Window > Script Manager, refresh the list, then run DisrobeAnalyzer"
}

install_binja() {
    if [ -z "${BINJA_PLUGINS}" ]; then
        if [ "$(uname)" = "Darwin" ]; then
            BINJA_PLUGINS="${HOME}/Library/Application Support/Binary Ninja/plugins"
        else
            BINJA_PLUGINS="${HOME}/.binaryninja/plugins"
        fi
    fi
    local dst="${BINJA_PLUGINS}/disrobe"
    echo "installing disrobe Binary Ninja plugin to ${dst}"
    rm -rf "${dst}"
    mkdir -p "${BINJA_PLUGINS}"
    cp -r "${SCRIPT_DIR}/binja" "${dst}"
    echo "done: plugin copied to ${dst}"
    echo "restart Binary Ninja to load the plugin"
}

case "${EDITOR}" in
    vscode) install_vscode ;;
    ida)    install_ida ;;
    ghidra) install_ghidra ;;
    binja)  install_binja ;;
    *)
        echo "unknown editor: ${EDITOR}" >&2
        usage
        ;;
esac
