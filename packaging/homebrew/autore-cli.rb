class AutoreCli < Formula
  desc "Bounded static reverse engineering for analysts and AI agents"
  homepage "https://github.com/timwhitez/AutoRE-CLI"
  version "0.1.6"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/timwhitez/AutoRE-CLI/releases/download/v0.1.6/AutoRE-CLI-0.1.6-macos-arm64.tar.gz"
      sha256 "d538dcef07d84da8c21e0e956d73812e0d32bb3631be8c85d2d591594cd722f4"
    else
      url "https://github.com/timwhitez/AutoRE-CLI/releases/download/v0.1.6/AutoRE-CLI-0.1.6-macos-x86_64.tar.gz"
      sha256 "ceb97b9fbb4c24cae6c74bfcf78bd989c63b5dd1f23dedd74dd8b35f1db61540"
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/timwhitez/AutoRE-CLI/releases/download/v0.1.6/AutoRE-CLI-0.1.6-linux-arm64.tar.gz"
      sha256 "0a35374f997c2e78176b5ac18b3e06b3201decc0c7e36c1d98ac6321939c6605"
    elsif Hardware::CPU.intel? && Hardware::CPU.is_64_bit?
      url "https://github.com/timwhitez/AutoRE-CLI/releases/download/v0.1.6/AutoRE-CLI-0.1.6-linux-x86_64.tar.gz"
      sha256 "9f2bfff39105262f00e584ce77853ac3397ac041049f3d7f27649f6aa69135e7"
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
