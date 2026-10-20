class AutoreCli < Formula
  desc "Bounded static reverse engineering for analysts and AI agents"
  homepage "https://github.com/timwhitez/AutoRE-CLI"
  version "0.1.13"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/timwhitez/AutoRE-CLI/releases/download/v0.1.13/AutoRE-CLI-0.1.13-macos-arm64.tar.gz"
      sha256 "e0cd60f3ae2981cbaed1948ec2394b4481c847b27e0db9f5a1d92335ff6efc35"
    else
      url "https://github.com/timwhitez/AutoRE-CLI/releases/download/v0.1.13/AutoRE-CLI-0.1.13-macos-x86_64.tar.gz"
      sha256 "5e07fd2e2ce948c90b9c992256ba31e8d6a67b8ffb183e9f6cb03bd8d4ab5fd7"
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/timwhitez/AutoRE-CLI/releases/download/v0.1.13/AutoRE-CLI-0.1.13-linux-arm64.tar.gz"
      sha256 "b39d1dd0466321bc1935aff82d01f71e6c3ae220942fe832f5269e8b655f1df9"
    elsif Hardware::CPU.intel? && Hardware::CPU.is_64_bit?
      url "https://github.com/timwhitez/AutoRE-CLI/releases/download/v0.1.13/AutoRE-CLI-0.1.13-linux-x86_64.tar.gz"
      sha256 "c431780a41f080bfdd2e4ade6da449c1005ba506e94158923e262464be286faf"
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
