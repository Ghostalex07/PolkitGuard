class Polkitguard < Formula
  desc "Security scanner for Linux Polkit policies"
  homepage "https://github.com/Ghostalex07/PolkitGuard"
  url "https://github.com/Ghostalex07/PolkitGuard/archive/refs/tags/v1.17.0.tar.gz"
  sha256 "REPLACE_WITH_ACTUAL_SHA256"
  license "MIT"
  version "1.17.0"

  bottle :unneeded

  depends_on "go" => :build

  def install
    system "go", "build", "-o", "polkitguard", "./cmd/scan"
    bin.install "polkitguard"
  end

  test do
    system "#{$bin}/polkitguard", "--version"
  end
end