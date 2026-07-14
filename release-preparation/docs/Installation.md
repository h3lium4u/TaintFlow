# Installation Guide

This document describes how to compile and install TaintFlow from source or binary artifacts.

## System Requirements
- **Operating System**: Windows 10/11, macOS Big Sur+, or Linux (CentOS/Ubuntu).
- **Rust Toolchain**: Rust 1.70.0+ (stable profile).
- **C/C++ Compiler**: GCC/Clang (for compiling tree-sitter C bindings).

---

## Installation Steps

### 1. Install Rust
Install Rust using `rustup`:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### 2. Clone the Repository
```bash
git clone https://github.com/taintflow/taintflow.git
cd taintflow/rust-engine
```

### 3. Compile Optimized Build
Build the production-ready optimized binary:
```bash
cargo build --release
```
The binary will be generated at `./target/release/taintflow-cli`.

---

## Verification
Verify the installation by querying the CLI version:
```bash
./target/release/taintflow-cli --version
```
For basic usage, refer to [QuickStart.md](QuickStart.md) or see [CLI.md](CLI.md) for parameter details.
