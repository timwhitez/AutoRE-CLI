class AutoreCli < Formula
  desc "Bounded static reverse engineering for analysts and AI agents"
  homepage "https://github.com/timwhitez/AutoRE-CLI"
  version "0.1.8"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/timwhitez/AutoRE-CLI/releases/download/v0.1.8/AutoRE-CLI-0.1.8-macos-arm64.tar.gz"
      sha256 "89b6043906c146507612a2abda054378809b12faefe1ef261bc259743a435802"
    else
      url "https://github.com/timwhitez/AutoRE-CLI/releases/download/v0.1.8/AutoRE-CLI-0.1.8-macos-x86_64.tar.gz"
      sha256 "120dc5be6f13ae8b57e1a0392fbc1d5f21b1365e90cbedf2a0b24dc80a5a4522"
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/timwhitez/AutoRE-CLI/releases/download/v0.1.8/AutoRE-CLI-0.1.8-linux-arm64.tar.gz"
      sha256 "514c4a95c5852b840b5af546ed33c7359d8755416b46acb4e43efdf424bb7581"
    elsif Hardware::CPU.intel? && Hardware::CPU.is_64_bit?
      url "https://github.com/timwhitez/AutoRE-CLI/releases/download/v0.1.8/AutoRE-CLI-0.1.8-linux-x86_64.tar.gz"
      sha256 "f72699d90bbfc6270f98d5d49f94ab94d3cea941186f5215489fcbce8aa82636"
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
