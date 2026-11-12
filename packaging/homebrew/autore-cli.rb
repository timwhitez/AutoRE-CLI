class AutoreCli < Formula
  desc "Bounded static reverse engineering for analysts and AI agents"
  homepage "https://github.com/timwhitez/AutoRE-CLI"
  version "0.1.14"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/timwhitez/AutoRE-CLI/releases/download/v0.1.14/AutoRE-CLI-0.1.14-macos-arm64.tar.gz"
      sha256 "d956f62ad7469fecfde378377d2cce9bbba51afbbc427a58773fc4a4e80ab833"
    else
      url "https://github.com/timwhitez/AutoRE-CLI/releases/download/v0.1.14/AutoRE-CLI-0.1.14-macos-x86_64.tar.gz"
      sha256 "ca93bb86864b5d219e5c8fbd5d4926e7cf04b46068250c105f82f6c2db6e817d"
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/timwhitez/AutoRE-CLI/releases/download/v0.1.14/AutoRE-CLI-0.1.14-linux-arm64.tar.gz"
      sha256 "05ebf0c08e3bfa944b0f2f63fe45d763cef379d9107064764bae43c49c201272"
    elsif Hardware::CPU.intel? && Hardware::CPU.is_64_bit?
      url "https://github.com/timwhitez/AutoRE-CLI/releases/download/v0.1.14/AutoRE-CLI-0.1.14-linux-x86_64.tar.gz"
      sha256 "f581473a5037e7911c35b27b37f16e959f3312e5608955e25606d1c1cb553b6d"
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
