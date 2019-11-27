#!/usr/bin/env bash
set -ex
make
./bench "$@"
