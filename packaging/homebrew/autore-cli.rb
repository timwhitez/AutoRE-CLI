class AutoreCli < Formula
  desc "Bounded static reverse engineering for analysts and AI agents"
  homepage "https://github.com/timwhitez/AutoRE-CLI"
  version "0.1.10"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/timwhitez/AutoRE-CLI/releases/download/v0.1.10/AutoRE-CLI-0.1.10-macos-arm64.tar.gz"
      sha256 "3c4d64be496c4b4e04b0b3ac8b545fa62b6ec71bb7ce6516a2456f22efccea9c"
    else
      url "https://github.com/timwhitez/AutoRE-CLI/releases/download/v0.1.10/AutoRE-CLI-0.1.10-macos-x86_64.tar.gz"
      sha256 "ef0187e04766d995d6f1a9358890f28450506444edfc0de99e79ccfea30ae183"
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/timwhitez/AutoRE-CLI/releases/download/v0.1.10/AutoRE-CLI-0.1.10-linux-arm64.tar.gz"
      sha256 "c93f0c20968831301122e0bc2c980455640ab7ee17ca412b0cabe2b8f4bb8413"
    elsif Hardware::CPU.intel? && Hardware::CPU.is_64_bit?
      url "https://github.com/timwhitez/AutoRE-CLI/releases/download/v0.1.10/AutoRE-CLI-0.1.10-linux-x86_64.tar.gz"
      sha256 "1f9e90a56ebf62cf6f9f866dd254d12726c71df50269eda06aba907430dd294d"
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
