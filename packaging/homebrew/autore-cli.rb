class AutoreCli < Formula
  desc "Bounded static reverse engineering for analysts and AI agents"
  homepage "https://github.com/timwhitez/AutoRE-CLI"
  version "0.1.3"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/timwhitez/AutoRE-CLI/releases/download/v0.1.3/AutoRE-CLI-0.1.3-macos-arm64.tar.gz"
      sha256 "3a823f1c368fb0ca59b45ace5ce6d637950aa2dac1c09bd2985996801f13a1d0"
    else
      url "https://github.com/timwhitez/AutoRE-CLI/releases/download/v0.1.3/AutoRE-CLI-0.1.3-macos-x86_64.tar.gz"
      sha256 "915cfb0d23891f14281d293ebf238a0dde6f1c3f4a1beb9e68793b5008740ccb"
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/timwhitez/AutoRE-CLI/releases/download/v0.1.3/AutoRE-CLI-0.1.3-linux-arm64.tar.gz"
      sha256 "f0573cfa92b0efd0b0b3776c6f47526241e1dd6584d01b37b074823c30521919"
    elsif Hardware::CPU.intel? && Hardware::CPU.is_64_bit?
      url "https://github.com/timwhitez/AutoRE-CLI/releases/download/v0.1.3/AutoRE-CLI-0.1.3-linux-x86_64.tar.gz"
      sha256 "56a6483325735cf4de5cab8e1c5b5c001c1185394b06dec201e2ab97fcecedb2"
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
