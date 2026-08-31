class AutoreCli < Formula
  desc "Bounded static reverse engineering for analysts and AI agents"
  homepage "https://github.com/timwhitez/AutoRE-CLI"
  version "0.1.2"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/timwhitez/AutoRE-CLI/releases/download/v0.1.2/AutoRE-CLI-0.1.2-macos-arm64.tar.gz"
      sha256 "c6924b8a827030fb5ed15cdc12318ca702088d3fd3dd86f7da17ce4d7fa39e9c"
    else
      url "https://github.com/timwhitez/AutoRE-CLI/releases/download/v0.1.2/AutoRE-CLI-0.1.2-macos-x86_64.tar.gz"
      sha256 "d94572a11a8ec1a3fe8c1ee7700fc0044174a6e81f854323c1ef724c558ee7c9"
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/timwhitez/AutoRE-CLI/releases/download/v0.1.2/AutoRE-CLI-0.1.2-linux-arm64.tar.gz"
      sha256 "44e163f1eb126f0f8d327baaa288bdcbf3962187af8ddef396984f792e6ffe7a"
    elsif Hardware::CPU.intel? && Hardware::CPU.is_64_bit?
      url "https://github.com/timwhitez/AutoRE-CLI/releases/download/v0.1.2/AutoRE-CLI-0.1.2-linux-x86_64.tar.gz"
      sha256 "32e8a69f841911f1b0280882fc3461d890198b7b63dc3f6c05b4ed80bd41bc2b"
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
