#!/bin/bash

pkg=github.com/jamesliu96/geheimnis
app=ghs
tag=$(git describe --tags --always)
rev=$(git rev-list -1 HEAD)
ldflags="-ldflags=-X main.gitTag=$tag -X main.gitRev=$rev"
out=$app.wasm
echo "# $pkg $tag $rev" 1>&2

printf "removing \"$out\" ... "
rm -rf $out \
  && echo "SUCCEEDED" \
  || echo "FAILED"
os=js
arch=wasm
printf "building \"$out\" ... "
CGO_ENABLED=0 \
GOOS=$os GOARCH=$arch \
  go build -trimpath "$ldflags -s -w" -o $out $pkg \
    && echo "SUCCEEDED" \
    || echo "FAILED"