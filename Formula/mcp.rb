class Mcp < Formula
  desc "CLI that turns MCP servers into terminal commands"
  homepage "https://github.com/avelino/mcp"
  version "0.5.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/avelino/mcp/releases/download/v0.5.0/mcp-aarch64-apple-darwin"
      sha256 "8833bbe814c45d9445adfdbaecb3e4a94ac6b506a93bd05729bfd7b1cdeb8557"
    else
      url "https://github.com/avelino/mcp/releases/download/v0.5.0/mcp-x86_64-apple-darwin"
      sha256 "929d2375bd69b396e3693ff75651e50ddfff235f375c83abf5cd983ff03a9d91"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/avelino/mcp/releases/download/v0.5.0/mcp-aarch64-unknown-linux-gnu"
      sha256 "31c704158bc9c4585b7aad63059f2d115c0de0573047cc943d044ef79e147c0e"
    else
      url "https://github.com/avelino/mcp/releases/download/v0.5.0/mcp-x86_64-unknown-linux-gnu"
      sha256 "a40b6b0e94ee20ec00c5532231ea29cd3dd6c6b57bf368c3c429c21a76ca777e"
    end
  end

  def install
    bin.install Dir.glob("mcp*").first => "mcp"
  end

  test do
    assert_match "mcp", shell_output("#{bin}/mcp --help")
  end
end
