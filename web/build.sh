#!/usr/bin/env bash
# Build the web sender's WebAssembly module into web/public/.
set -euo pipefail
cd "$(dirname "$0")/spake2-wasm"
cargo build --release --target wasm32-unknown-unknown
cp target/wasm32-unknown-unknown/release/wormhole_spake2_wasm.wasm ../public/spake2.wasm
ls -l ../public/spake2.wasm
