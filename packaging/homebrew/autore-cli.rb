class AutoreCli < Formula
  desc "Bounded static reverse engineering for analysts and AI agents"
  homepage "https://github.com/timwhitez/AutoRE-CLI"
  version "0.1.1"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/timwhitez/AutoRE-CLI/releases/download/v0.1.1/AutoRE-CLI-0.1.1-macos-arm64.tar.gz"
      sha256 "29a9ed496d64875aa12d42b1314aa0ed194b8e964e22e8ad58eceed666599b85"
    else
      url "https://github.com/timwhitez/AutoRE-CLI/releases/download/v0.1.1/AutoRE-CLI-0.1.1-macos-x86_64.tar.gz"
      sha256 "11ca2f29b78ef11436c3af28969a545ba60e5093400eff8c054c1e5bf056c54d"
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/timwhitez/AutoRE-CLI/releases/download/v0.1.1/AutoRE-CLI-0.1.1-linux-arm64.tar.gz"
      sha256 "ec85079182c8e829af2e8ed3b7b8dcdb9a4d98f3cc5918001a43c6c3269d8b30"
    elsif Hardware::CPU.intel? && Hardware::CPU.is_64_bit?
      url "https://github.com/timwhitez/AutoRE-CLI/releases/download/v0.1.1/AutoRE-CLI-0.1.1-linux-x86_64.tar.gz"
      sha256 "be047d6163924c46184b88d7b32fdb3ac5e806a73a3955654616a0ab03c47b8a"
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
