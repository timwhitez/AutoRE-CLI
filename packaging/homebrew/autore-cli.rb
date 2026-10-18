class AutoreCli < Formula
  desc "Bounded static reverse engineering for analysts and AI agents"
  homepage "https://github.com/timwhitez/AutoRE-CLI"
  version "0.1.12"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/timwhitez/AutoRE-CLI/releases/download/v0.1.12/AutoRE-CLI-0.1.12-macos-arm64.tar.gz"
      sha256 "3d3b95c33a7d716676d64657428ca5fc235373797dd3fc42fa3757fe5517daf9"
    else
      url "https://github.com/timwhitez/AutoRE-CLI/releases/download/v0.1.12/AutoRE-CLI-0.1.12-macos-x86_64.tar.gz"
      sha256 "f39b7bd1e0b806da11bbd075644d13073c71c537f2782fc70d27bb0df295fca7"
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/timwhitez/AutoRE-CLI/releases/download/v0.1.12/AutoRE-CLI-0.1.12-linux-arm64.tar.gz"
      sha256 "58a13f6eddee28698ca34745b84104b578c6f4b146774fc2833a3afc78313181"
    elsif Hardware::CPU.intel? && Hardware::CPU.is_64_bit?
      url "https://github.com/timwhitez/AutoRE-CLI/releases/download/v0.1.12/AutoRE-CLI-0.1.12-linux-x86_64.tar.gz"
      sha256 "b4528cc78600d852cf46342b1a9faef1009e1b957595eae117b14e7ceb53a740"
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
