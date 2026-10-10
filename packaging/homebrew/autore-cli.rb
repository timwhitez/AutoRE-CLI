class AutoreCli < Formula
  desc "Bounded static reverse engineering for analysts and AI agents"
  homepage "https://github.com/timwhitez/AutoRE-CLI"
  version "0.1.11"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/timwhitez/AutoRE-CLI/releases/download/v0.1.11/AutoRE-CLI-0.1.11-macos-arm64.tar.gz"
      sha256 "161022fd85940743a6c3f93b1daadfc62e54e2c3d5f5048dd31cb1f104c3b075"
    else
      url "https://github.com/timwhitez/AutoRE-CLI/releases/download/v0.1.11/AutoRE-CLI-0.1.11-macos-x86_64.tar.gz"
      sha256 "d61b60d74f31639bafd3374d4316b6d46463b1bfc43cac6038061f93807d0241"
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/timwhitez/AutoRE-CLI/releases/download/v0.1.11/AutoRE-CLI-0.1.11-linux-arm64.tar.gz"
      sha256 "bc7f8a3ef0cf5e4661b9d0ceae241a2e6134e34f19c0bdb0f4d9fba6908aa2e3"
    elsif Hardware::CPU.intel? && Hardware::CPU.is_64_bit?
      url "https://github.com/timwhitez/AutoRE-CLI/releases/download/v0.1.11/AutoRE-CLI-0.1.11-linux-x86_64.tar.gz"
      sha256 "10a42c7c9dc1a62df0a66bc7d17541cb3fc3d0dfc1d076912c8593829e26062e"
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
