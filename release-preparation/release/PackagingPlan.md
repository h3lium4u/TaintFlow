# Packaging Plan

This document details the automated scripts and packaging steps required to bundle release artifacts.

---

## Packaging Steps

### 1. Compile Targets
On each runner platform, compile with release optimization:
```bash
cargo build --release
```

### 2. Assembly & Compression

#### Linux / macOS
```bash
mkdir -p dist/taintflow-cli
cp target/release/taintflow-cli dist/taintflow-cli/
cp ../LICENSE dist/taintflow-cli/
cp ../README.md dist/taintflow-cli/
tar -czf taintflow-cli-x86_64-unknown-linux-gnu.tar.gz -C dist taintflow-cli
```

#### Windows (PowerShell)
```powershell
New-Item -ItemType Directory -Path "dist\taintflow-cli" -Force
Copy-Item "target\release\taintflow-cli.exe" "dist\taintflow-cli\"
Copy-Item "..\LICENSE" "dist\taintflow-cli\"
Copy-Item "..\README.md" "dist\taintflow-cli\"
Compress-Archive -Path "dist\taintflow-cli" -DestinationPath "taintflow-cli-x86_64-pc-windows-msvc.zip"
```

For distribution details, see [DistributionChannels.md](DistributionChannels.md).
