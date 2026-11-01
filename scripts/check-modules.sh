#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
set -eu

if [ -d vendor ] || [ -d pkg/sagernet ]; then
  echo 'local vendored protocol modules are not allowed' >&2
  exit 1
fi

local_replacements=$(go list -m -f '{{if .Replace}}{{if not .Replace.Version}}{{.Path}}{{end}}{{end}}' all)
if [ -n "$local_replacements" ]; then
  echo 'local module replacements are not allowed' >&2
  exit 1
fi

modules=$(go list -m -f '{{.Path}}:{{.Indirect}}' all)
case "$modules" in
  *'github.com/sagernet/sing:false'*) ;;
  *) echo 'sing must remain a direct dependency' >&2; exit 1 ;;
esac
case "$modules" in
  *'github.com/sagernet/sing-box:'*) echo 'sing-box must not be a module dependency' >&2; exit 1 ;;
esac
