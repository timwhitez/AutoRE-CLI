class AutoreCli < Formula
  desc "Bounded static reverse engineering for analysts and AI agents"
  homepage "https://github.com/timwhitez/AutoRE-CLI"
  version "0.1.11"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/timwhitez/AutoRE-CLI/releases/download/v0.1.11/AutoRE-CLI-0.1.11-macos-arm64.tar.gz"
      sha256 "cc79df734b5c3bba272638ba03539481b18996a245c67cbf981ec5de66993d97"
    else
      url "https://github.com/timwhitez/AutoRE-CLI/releases/download/v0.1.11/AutoRE-CLI-0.1.11-macos-x86_64.tar.gz"
      sha256 "36685c3e2614e2ba235b90808b71098e3a98b7745959e197c0d0b849061ffb03"
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/timwhitez/AutoRE-CLI/releases/download/v0.1.11/AutoRE-CLI-0.1.11-linux-arm64.tar.gz"
      sha256 "7aa16f0aa60e7fdce48a400b929d5ef7c9a05179d6cbcc4a398edb5a4a44028b"
    elsif Hardware::CPU.intel? && Hardware::CPU.is_64_bit?
      url "https://github.com/timwhitez/AutoRE-CLI/releases/download/v0.1.11/AutoRE-CLI-0.1.11-linux-x86_64.tar.gz"
      sha256 "332cca05eee4ef6e5becc5c142340623ce708e00be40b03cf212b23f94acc752"
    else
      odie "AutoRE-CLI has no release for this Linux architecture"
    end
  end

  def install
    binary = if OS.mac?
      Hardware::CPU.arm? ? "bin/macos-arm64/auto-re-cli" : "bin/macos-x86_64/auto-re-cli"
    elsif Hardware::CPU.arm?
      "bin/linux-arm64/auto-re-cli"
    else
      "bin/linux-x86_64/auto-re-cli"
    end
    bin.install binary => "auto-re-cli"
  end

  test do
    assert_equal "auto-re-cli #{version}", shell_output("#{bin}/auto-re-cli --version").strip
  end
end
