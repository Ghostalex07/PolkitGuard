#!/bin/bash

set -e

VERSION="1.18.0"
BINARY_NAME="polkitguard"

install_polkitguard() {
    echo "Installing PolkitGuard v${VERSION}..."

    if command -v sudo &> /dev/null; then
        SUDO="sudo"
    else
        SUDO=""
    fi

    INSTALL_DIR="${DESTDIR:-}/usr/local/bin"
    ${SUDO} mkdir -p "${INSTALL_DIR}"

    if [ -f "/usr/local/bin/polkitguard" ]; then
        ${SUDO} cp "/usr/local/bin/polkitguard" "/usr/local/bin/polkitguard.bak.$(date +%s)"
    fi

    if [ -f "polkitguard" ]; then
        ${SUDO} cp "polkitguard" "${INSTALL_DIR}/${BINARY_NAME}"
    elif [ -f "/home/vaca/github/PolkitGuard/polkitguard" ]; then
        ${SUDO} cp "/home/vaca/github/PolkitGuard/polkitguard" "${INSTALL_DIR}/${BINARY_NAME}"
    else
        echo "Error: polkitguard binary not found in current directory"
        exit 1
    fi

    ${SUDO} chmod +x "${INSTALL_DIR}/${BINARY_NAME}"

    echo "Installed to ${INSTALL_DIR}/${BINARY_NAME}"

    if [ -f "polkitguard.1" ]; then
        MANDIR="${DESTDIR:-}/usr/local/share/man/man1"
        ${SUDO} mkdir -p "${MANDIR}"
        ${SUDO} cp "polkitguard.1" "${MANDIR}/"
        ${SUDO} mandb "${MANDIR}" 2>/dev/null || true
        echo "Man page installed"
    fi

    echo "Installation complete!"
}

uninstall_polkitguard() {
    echo "Uninstalling PolkitGuard..."

    if command -v sudo &> /dev/null; then
        SUDO="sudo"
    else
        SUDO=""
    fi

    ${SUDO} rm -f "/usr/local/bin/polkitguard"
    ${SUDO} rm -f "/usr/local/share/man/man1/polkitguard.1"

    echo "Uninstalled!"
}

case "$1" in
    install)
        install_polkitguard
        ;;
    uninstall)
        uninstall_polkitguard
        ;;
    *)
        echo "Usage: $0 {install|uninstall}"
        exit 1
        ;;
esac