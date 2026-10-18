class AutoreCli < Formula
  desc "Bounded static reverse engineering for analysts and AI agents"
  homepage "https://github.com/timwhitez/AutoRE-CLI"
  version "0.1.12"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/timwhitez/AutoRE-CLI/releases/download/v0.1.12/AutoRE-CLI-0.1.12-macos-arm64.tar.gz"
      sha256 "bad5388a7d8386adec719f56a935543faa86e851724c7e4af76c4f8ecbf29697"
    else
      url "https://github.com/timwhitez/AutoRE-CLI/releases/download/v0.1.12/AutoRE-CLI-0.1.12-macos-x86_64.tar.gz"
      sha256 "f368e36e3139b08134339bb5c69f206dc77864a6f7d6bf335bee3420239181e5"
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/timwhitez/AutoRE-CLI/releases/download/v0.1.12/AutoRE-CLI-0.1.12-linux-arm64.tar.gz"
      sha256 "2c426b5adeeafcd6e971d5795f61c8c25f97e6ce80f19bc2d224a28c187c5894"
    elsif Hardware::CPU.intel? && Hardware::CPU.is_64_bit?
      url "https://github.com/timwhitez/AutoRE-CLI/releases/download/v0.1.12/AutoRE-CLI-0.1.12-linux-x86_64.tar.gz"
      sha256 "8c784651a376d507a5a31b9a98a25e0fd32ec2806ad14a09fed9539910858d88"
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
