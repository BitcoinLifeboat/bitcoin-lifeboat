# Homebrew formula template for the Bitcoin Lifeboat CLI.
#
# Replace __GH_ORG__ and the __SHA256_*__ placeholders when cutting a concrete
# release. The formula installs the CLI archive produced by .github/workflows/release.yml.
class BitcoinLifeboat < Formula
  desc "Local-first Bitcoin recovery readiness CLI"
  homepage "https://bitcoinlifeboat.org"
  license "MIT"
  version "0.2.0-alpha.1"

  if OS.mac?
    url "https://github.com/__GH_ORG__/bitcoin-lifeboat/releases/download/v#{version}/bitcoin-lifeboat-v#{version}-cli-macos-universal.tar.gz"
    sha256 "__SHA256_CLI_MACOS_UNIVERSAL__"
  elsif OS.linux?
    url "https://github.com/__GH_ORG__/bitcoin-lifeboat/releases/download/v#{version}/bitcoin-lifeboat-v#{version}-cli-linux-x86_64.tar.gz"
    sha256 "__SHA256_CLI_LINUX_X86_64__"
  end

  def install
    bin.install "lifeboat"
    prefix.install "README.md"
    prefix.install "LICENSE"
  end

  test do
    assert_match "lifeboat", shell_output("#{bin}/lifeboat --version")
  end
end
