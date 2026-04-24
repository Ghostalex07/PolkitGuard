Name: polkitguard
Version: 1.3.0
Release: 1%{?dist}
Summary: Security scanner for Linux Polkit
License: MIT
URL: https://github.com/Ghostalex07/PolkitGuard
Requires: glibc >= 2.17

%description
PolkitGuard scans Linux Polkit configurations for security issues.

%install
install -Dm755 polkitguard %{buildroot}%{_bindir}/polkitguard
install -Dm644 config.schema.json %{buildroot}%{_datadir}/polkitguard/config.schema.json

%files
%{_bindir}/polkitguard
%{_datadir}/polkitguard/config.schema.json