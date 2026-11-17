#!/usr/bin/env bash
# Mint one NATS password: the letter `n`, then 32 bytes of the operating
# system's randomness as 64 hexadecimal characters (2026-10-30,
# docs/engineering-log/packages/2026-10-30-nats-password-lexes-as-a-string.md).
#
#   scripts/nats-password.sh        prints the password and a newline
#
# The one home of the shape, used by every minter of NATS_PASSWORD,
# NATS_WORKER_PASSWORD and NATS_CLUSTER_PASSWORD (scripts/minimal-env.sh,
# scripts/setup-dev.sh, the Makefile's `.env` back-fill, deploy/k3s/install.sh);
# scripts/tests/nats-password-test.sh holds them to it.
#
# Why the letter: deploy/nats/nats.conf and the chart's ConfigMap reference the
# passwords as unquoted `$NATS_PASSWORD`, and nats-server resolves such a
# reference by LEXING the environment value as a config token
# (conf/parse.go `lookupVariable`: `Parse("<key>=<value>")`). A value whose
# first rune is a digit is read as a number (conf/lex.go
# `lexNumberOrDateOrStringOrIP`): `2e0f…` and `2eb0…` are an integer with a
# size suffix followed by junk ("Expected a top-level value to end with a new
# line, comment or EOF, but got '0' instead") and 64 digits are "out of the
# range"; the server refuses to start. The grammar offers no way to quote a
# resolved reference — `"$NATS_PASSWORD"` is the literal string — so the value
# itself must lex as a string, and a value whose first rune is a letter is
# read by `lexString` from that rune with no number path at all. Roughly one
# 64-hex mint in forty began `<digits>e<digit>`.
#
# `od` is POSIX; no openssl is needed. The length is checked: a short read
# would be a weak key.
set -euo pipefail

v="$(od -An -tx1 -N32 /dev/urandom | tr -d ' \n')"
if [ "${#v}" -ne 64 ]; then
    printf 'nats-password.sh: the random source returned %s hex characters, not 64 — refusing to mint a weak password\n' "${#v}" >&2
    exit 1
fi
printf 'n%s\n' "$v"
