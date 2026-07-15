class Taintflow < Formula
  desc "TaintFlow static application security testing (SAST) engine"
  homepage "https://github.com/h3lium4u/TaintFlow"
  url "https://github.com/h3lium4u/TaintFlow/releases/download/v1.0.0/taintflow-cli-x86_64-apple-darwin.tar.gz"
  sha256 "0000000000000000000000000000000000000000000000000000000000000000" # Updated dynamically on release tag cut
  version "1.0.0"

  def install
    bin.install "taintflow-cli"
  end

  test do
    system "#{bin}/taintflow-cli", "--help"
  end
end
