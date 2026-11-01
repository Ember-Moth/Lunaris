#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
set -eu

modules=$(go list -m -f '{{.Path}}:{{.Indirect}}' all)
case "$modules" in
  *'github.com/sagernet/sing:false'*) ;;
  *) echo 'sing must remain a direct dependency' >&2; exit 1 ;;
esac
case "$modules" in
  *'github.com/sagernet/sing-box:'*) echo 'sing-box must not be a module dependency' >&2; exit 1 ;;
esac
