class AutoreCli < Formula
  desc "Bounded static reverse engineering for analysts and AI agents"
  homepage "https://github.com/timwhitez/AutoRE-CLI"
  version "0.1.5"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/timwhitez/AutoRE-CLI/releases/download/v0.1.5/AutoRE-CLI-0.1.5-macos-arm64.tar.gz"
      sha256 "46c69d482a80de8aa1346be6698f8e1603cfee1fd7fcd399571e6e9c329efa11"
    else
      url "https://github.com/timwhitez/AutoRE-CLI/releases/download/v0.1.5/AutoRE-CLI-0.1.5-macos-x86_64.tar.gz"
      sha256 "3a9a446664a31cea2134eb1b171d5dfba0cb184dbf9bce6b06323d7170daba3a"
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/timwhitez/AutoRE-CLI/releases/download/v0.1.5/AutoRE-CLI-0.1.5-linux-arm64.tar.gz"
      sha256 "411062a1138b702034a99266d20be889000522f9697084ffc15de43478095e60"
    elsif Hardware::CPU.intel? && Hardware::CPU.is_64_bit?
      url "https://github.com/timwhitez/AutoRE-CLI/releases/download/v0.1.5/AutoRE-CLI-0.1.5-linux-x86_64.tar.gz"
      sha256 "4594eccac665560415d7801ffd8a9fd1831918093de8d315d05c80d3c344f468"
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
