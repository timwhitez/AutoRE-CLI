class AutoreCli < Formula
  desc "Bounded static reverse engineering for analysts and AI agents"
  homepage "https://github.com/timwhitez/AutoRE-CLI"
  version "0.1.9"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/timwhitez/AutoRE-CLI/releases/download/v0.1.9/AutoRE-CLI-0.1.9-macos-arm64.tar.gz"
      sha256 "41b56a6b03821f34d17d2c83cf8a3c7c76cb9961cba6881cc0ee3d9e46029042"
    else
      url "https://github.com/timwhitez/AutoRE-CLI/releases/download/v0.1.9/AutoRE-CLI-0.1.9-macos-x86_64.tar.gz"
      sha256 "9834d845f978b3817c6f7e730062666d5ecb534878b0176ef60a4719c2292930"
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/timwhitez/AutoRE-CLI/releases/download/v0.1.9/AutoRE-CLI-0.1.9-linux-arm64.tar.gz"
      sha256 "de0074d1a48822e85a818fd1cbbb6e0aa3446a5eb38dc602ed2c425cac820f0b"
    elsif Hardware::CPU.intel? && Hardware::CPU.is_64_bit?
      url "https://github.com/timwhitez/AutoRE-CLI/releases/download/v0.1.9/AutoRE-CLI-0.1.9-linux-x86_64.tar.gz"
      sha256 "7738e6d223ce36d01e755df1651f5cb88d0d192a8a1155a808d3cba81f74ed77"
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
