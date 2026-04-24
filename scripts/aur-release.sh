#!/bin/bash
# AUR Release Script for PolkitGuard
# Usage: ./scripts/aur-release.sh v1.6.0

set -e

VERSION="${1}"
if [ -z "$VERSION" ]; then
    echo "Usage: $0 <version>"
    exit 1
fi

TAG="v$VERSION"
REPO_DIR="/tmp/polkitguard-aur"

echo "Creating AUR release for $TAG..."

# Clone or create AUR repo
mkdir -p "$REPO_DIR"
cd "$REPO_DIR"

# Create PKGBUILD
cat > PKGBUILD << EOF
pkgname=polkitguard
pkgver=${VERSION#v}
pkgrel=1
pkgdesc="Security scanner for Linux Polkit configurations"
arch=('x86_64')
license=('MIT')
provides=('polkitguard')
source=("polkitguard-\${pkgver}.tar.gz::https://github.com/Ghostalex07/PolkitGuard/archive/\${pkgver}.tar.gz")
md5sums=('SKIP')

package() {
  cd "\${pkgname}-\${pkgver}"
  install -Dm755 polkitguard "\${pkgdir}/usr/bin/polkitguard"
  install -Dm644 config.schema.json "\${pkgdir}/usr/share/polkitguard/config.schema.json"
  install -Dm644 LICENSE "\${pkgdir}/usr/share/licenses/polkitguard/LICENSE"
}

EOF

# Download binary or build
echo "Note: Upload to AUR manually using:"
echo "  cd $REPO_DIR"
echo "  makepkg --skipinteg"
echo "  aur submit PKGBUILD"

echo "AUR package created at: $REPO_DIR"