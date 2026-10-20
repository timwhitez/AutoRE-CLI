class AutoreCli < Formula
  desc "Bounded static reverse engineering for analysts and AI agents"
  homepage "https://github.com/timwhitez/AutoRE-CLI"
  version "0.1.13"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/timwhitez/AutoRE-CLI/releases/download/v0.1.13/AutoRE-CLI-0.1.13-macos-arm64.tar.gz"
      sha256 "09ced7ccca0f840a209ae963abd4f3553e171f3ae567a47486df53e851af86e9"
    else
      url "https://github.com/timwhitez/AutoRE-CLI/releases/download/v0.1.13/AutoRE-CLI-0.1.13-macos-x86_64.tar.gz"
      sha256 "807b0d893bcca9edd261a49404363971f2a271e85cf90f4d35fbd3ca1a207bf0"
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/timwhitez/AutoRE-CLI/releases/download/v0.1.13/AutoRE-CLI-0.1.13-linux-arm64.tar.gz"
      sha256 "7a182220cb8d0fc5821e7ae50455a57d6601ee3d024609bdcad4068bb2a55078"
    elsif Hardware::CPU.intel? && Hardware::CPU.is_64_bit?
      url "https://github.com/timwhitez/AutoRE-CLI/releases/download/v0.1.13/AutoRE-CLI-0.1.13-linux-x86_64.tar.gz"
      sha256 "33c8003a33c974228820b289007fcddc37421aea4a6ef1aaa3fd5b35b4016e5d"
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
