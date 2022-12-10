#!/bin/bash

set -e

version=$(grep -o -E 'v[[:digit:]]+\.[[:digit:]]+\.[[:digit:]]+' version.js)

curl -L https://github.com/jamesliu96/geheim/releases/download/$version/xp_js_wasm.wasm > xp/xp.wasm