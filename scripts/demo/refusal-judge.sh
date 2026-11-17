#!/usr/bin/env bash
# The judge of the refusal demo (docs/refusal-demo.md): the table of the five
# attempts, and the part that decides pass or fail over what a run recorded.
#
#   scripts/demo/refusal-judge.sh --judge <report.json> <worker-lines.txt>
#   scripts/demo/refusal-judge.sh --print-table
#
# `--judge` reads the report the hostile module returned
# (scripts/demo/hostile-module.rs) and the worker's `[host:…]` lines for that
# run. For each attempt it prints what was asked, what the caller was given,
# the line the worker recorded, and the source file and line the deciding
# function is declared on. Exit 0 = both controls served and every attempt
# that was made refused. Exit 1 = an attempt was admitted, a control was
# refused, or the judge could not tell. Needs jq; python3 if present checks
# the control's HMAC.
#
# The run that made the attempts says the rest in the environment:
#   DEMO_JUDGE_GRANTED_VALUE     the stored secret, to check the control's MAC
#   DEMO_JUDGE_JOB_ID            the job the fifth attempt named
#   DEMO_JUDGE_LIVE_RC / DEMO_JUDGE_ENDED_RC   the probe's two exit statuses:
#                                the fifth attempt while the job ran, and after
#   DEMO_JUDGE_LIVE_OUT / DEMO_JUDGE_ENDED_OUT what the probe printed
#   DEMO_JUDGE_COUNT_BEFORE / DEMO_JUDGE_COUNT_AFTER   the controller's refusal
#                                count around the fifth attempt
#   DEMO_JUDGE_COUNTER           the name that count is read under
#   DEMO_JUDGE_FIFTH=0           the caller judges the fifth attempt itself,
#                                and this judges four
#   AEGIX_DEMO_REQUIRE_ALL=1     a fifth attempt that was not made is a failure
#
# `--print-table` prints the table below: the one home of the five rows.
#
# A script that makes the attempts itself sources this file and calls `judge`.
set -euo pipefail

JUDGE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HMAC_MESSAGE="talos-refusal-demo"

red()    { printf '\033[1;31m%s\033[0m\n' "$*" >&2; }
green()  { printf '\033[1;32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[1;33m%s\033[0m\n' "$*"; }
dim()    { printf '\033[2m%s\033[0m\n' "$*"; }
bold()   { printf '\033[1m%s\033[0m\n' "$*"; }
die()    { red "✗ $*"; exit 1; }

# ── What decides each attempt ────────────────────────────────────────────────
# One table: the attempt, what the caller must be given, the policy token the
# refusal is recorded under, and where the decision is made (a file and a
# pattern that finds the deciding function in it). The line printed is the one
# that function is declared on, read from the tree when this runs, so it
# cannot go stale.
#   id | title | expected | policy | file | pattern
ATTEMPTS='ungranted-secret|read a secret it was not granted|Err(unauthorized)|secret-allowlist|aegix-worker-runtime/src/host/vault.rs|fn check_secret_allowlist
unlisted-host|call a host that is not on its list|Err(forbiddenhost)|allowed-hosts|aegix-worker-runtime/src/host/egress_admission.rs|fn admit_parsed_url
external-model|reach an external model as a local-only actor|Err(forbiddenhost)|tier1-llm-egress|aegix-worker-runtime/src/host/egress.rs|fn egress_posture_deny_reason
memory-write|write as a read-only actor|Err(not-available)|write-ceiling|aegix-worker-runtime/src/context.rs|pub async fn write_ceiling_refuses_detailed
ended-job|ask for its data after its job has ended|Unauthorized|not_live|aegix-rpc-gates/src/dispatch_binding.rs|pub async fn gate'

field() { printf '%s\n' "$ATTEMPTS" | awk -F'|' -v id="$1" -v n="$2" '$1 == id { print $n }'; }
# "path:line" of the deciding function, or the path alone outside a checkout.
where() {
    local file pattern line
    file="$(field "$1" 5)"; pattern="$(field "$1" 6)"
    line="$(grep -n -m1 -E "$pattern" "$JUDGE_ROOT/$file" 2>/dev/null | cut -d: -f1 || true)"
    if [ -n "$line" ]; then printf '%s:%s' "$file" "$line"; else printf '%s' "$file"; fi
}

FAILURES=0; SHOWN=0
fail() { red "     ✗ $*"; FAILURES=$(( FAILURES + 1 )); }
# Everything that decides pass or fail. Reads REPORT (the module's JSON),
# HOST_LINES (the worker's `[host:…]` lines), GRANTED_VALUE, and for the fifth
# attempt OUTSIDE, LIVE_RC/LIVE_OUT, ENDED_RC/ENDED_OUT, COUNT_BEFORE/_AFTER.
judge() {
    got()      { printf '%s' "$REPORT" | jq -r --arg i "$1" '.steps[] | select(.id == $i) | .got'; }
    outcome()  { printf '%s' "$REPORT" | jq -r --arg i "$1" '.steps[] | select(.id == $i) | .outcome'; }
    call_of()  { printf '%s' "$REPORT" | jq -r --arg i "$1" '.steps[] | select(.id == $i) | .call'; }
    host_line() { printf '%s\n' "$HOST_LINES" | grep -F "denied by policy '$1'" | head -1 || true; }

    printf '\n'
    bold "What the module was entitled to (the controls: a refusal below is not a worker that refuses everything)"
    # granted-secret: served, and the MAC is the one the stored value gives.
    printf '\n  \033[1m%s\033[0m\n' "use a secret it was granted, without reading it"
    printf '     %-10s %s\n' "asked" "$(call_of granted-secret)"
    if [ "$(outcome granted-secret)" = served ]; then
        mac="$(got granted-secret)"; mac="${mac#hmac:}"
        printf '     %-10s %s\n' "given" "an opaque handle; the host computed HMAC-SHA256 ${mac:0:16}… over a fixed message"
        if [ -z "${GRANTED_VALUE:-}" ]; then
            green "     ✓ served (no stored value was given to check the MAC against)"
        elif command -v python3 >/dev/null 2>&1; then
            expected="$(printf '%s' "$GRANTED_VALUE" | python3 -I -c 'import hmac,hashlib,sys; print(hmac.new(sys.stdin.buffer.read(), sys.argv[1].encode(), hashlib.sha256).hexdigest())' "$HMAC_MESSAGE")"
            if [ "$mac" = "$expected" ]; then
                green "     ✓ served — the MAC is the one the stored value gives; the value never entered the module"
            else
                fail "the MAC is not the one the stored value gives: the secret the module used is not the one stored"
            fi
        else
            green "     ✓ served (python3 is not installed, so the MAC was not checked against the stored value)"
        fi
    else
        fail "the control was refused: $(got granted-secret) — a refusal below would prove nothing"
    fi
    printf '\n  \033[1m%s\033[0m\n' "read its actor's memory"
    printf '     %-10s %s\n' "asked" "$(call_of memory-read)"
    printf '     %-10s %s\n' "given" "$(got memory-read)"
    if [ "$(outcome memory-read)" = served ] && grep -q 'left here by the operator' <<<"$(got memory-read)"; then
        green "     ✓ served — over the signed data plane, as the bound actor, while its job was live"
    else
        fail "the control was not served what the operator left"
    fi

    printf '\n'
    bold "What it tried, and was refused"
    n=0
    for id in ungranted-secret unlisted-host external-model memory-write; do
        n=$(( n + 1 ))
        title="$(field "$id" 2)"; expected="$(field "$id" 3)"; policy="$(field "$id" 4)"
        printf '\n  \033[1m%s. %s\033[0m\n' "$n" "$title"
        printf '     %-10s %s\n' "asked" "$(call_of "$id")"
        printf '     %-10s %s\n' "given" "$(got "$id")"
        line="$(host_line "$policy")"
        printf '     %-10s %s\n' "worker" "${line:-(no line recorded under policy '$policy')}"
        printf '     %-10s %s\n' "decided in" "$(where "$id")"
        SHOWN=$(( SHOWN + 1 ))
        if [ -z "$(outcome "$id")" ]; then
            fail "the module's report has no step '$id'"
        elif [ "$(outcome "$id")" != refused ]; then
            fail "NOT REFUSED: the module was given $(got "$id")"
        elif [ "$(got "$id")" != "$expected" ]; then
            fail "refused, but with $(got "$id") where $expected is the refusal this demo names"
        elif [ -z "$line" ]; then
            fail "refused, but the worker's log for this execution has no line under policy '$policy'"
        else
            green "     ✓ refused"
        fi
    done
    # The log names the refused secret only by the SHA-256 of its path.
    if command -v python3 >/dev/null 2>&1; then
        path_hash="$(python3 -I -c 'import hashlib; print(hashlib.sha256(b"demo/not-granted").hexdigest())')"
        grep -q "$path_hash" <<<"$(host_line secret-allowlist)" \
            || fail "the secret refusal's target is not the SHA-256 of the path the module asked for"
    fi

    id=ended-job
    [ "${FIFTH:-1}" = 1 ] || return 0
    printf '\n  \033[1m5. %s\033[0m\n' "$(field "$id" 2)"
    if [ "$OUTSIDE" = 1 ]; then
        SHOWN=$(( SHOWN + 1 ))
        printf '     %-10s %s\n' "asked" "talos.memory.op Get \"demo/readable\", signed with the fleet key, bound to job $JOB_ID"
        printf '     %-10s %s\n' "" "(sent by a process outside the module that holds what a worker on this stack holds)"
        # The probe's own line is long (the whole reply); say what it was given.
        if [ "$LIVE_RC" = 2 ] && grep -q 'left here by the operator' <<<"$LIVE_OUT"; then
            printf '     %-10s %s\n' "job live" "served: \"left here by the operator\""
        else
            printf '     %-10s %s\n' "job live" "$(printf '%s' "$LIVE_OUT" | tail -1 | cut -c1-200)"
        fi
        if [ "$ENDED_RC" = 0 ]; then
            printf '     %-10s %s\n' "job ended" "refused: Unauthorized"
        else
            printf '     %-10s %s\n' "job ended" "$(printf '%s' "$ENDED_OUT" | tail -1 | cut -c1-200)"
        fi
        if [ -n "$COUNT_BEFORE" ] && [ -n "$COUNT_AFTER" ]; then
            counter_name="${COUNTER_NAME:-}"
            [ -n "$counter_name" ] || counter_name='aegix_rpc_dispatch_binding_refusals_total{subject="talos.memory.op",reason="not_live"}'
            printf '     %-10s %s\n' "controller" "$counter_name: $COUNT_BEFORE → $COUNT_AFTER"
        else
            printf '     %-10s %s\n' "controller" "event_kind=rpc_dispatch_binding_refused reason=not_live, in its log (its metrics are not readable from here)"
        fi
        printf '     %-10s %s\n' "decided in" "$(where "$id")"
        if [ "$LIVE_RC" != 2 ] || ! grep -q 'left here by the operator' <<<"$LIVE_OUT"; then
            fail "while the job was live the request was not served the actor's data (probe exit $LIVE_RC): the refusal after it cannot be told from a request that is always refused"
        elif [ "$ENDED_RC" = 2 ]; then
            fail "NOT REFUSED: the request was served after the job had ended"
        elif [ "$ENDED_RC" != 0 ]; then
            fail "the probe could not tell (exit $ENDED_RC): $(printf '%s' "$ENDED_OUT" | tail -1)"
        elif [ -n "$COUNT_BEFORE" ] && [ -n "$COUNT_AFTER" ] && [ "$COUNT_AFTER" = "$COUNT_BEFORE" ]; then
            fail "refused, but the controller's refusal count did not move"
        else
            green "     ✓ served while the job ran, refused once it had ended: one request, one key, one difference"
        fi
    else
        yellow "     not run: $OUTSIDE_WHY"
        [ -z "${NOT_RUN_HINT:-}" ] || dim "     $NOT_RUN_HINT"
        printf '     %-10s %s\n' "decided in" "$(where "$id")"
    fi
}

# Run, and not sourced: judge what the caller recorded.
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    if [ "${1:-}" = "--print-table" ]; then
        printf '%s\n' "$ATTEMPTS"
        exit 0
    fi
    if [ "${1:-}" != "--judge" ]; then
        sed -n '2,7p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2
        exit 2
    fi
    command -v jq >/dev/null 2>&1 || die "missing required tool: jq"
    [ -r "${2:-}" ] && [ -r "${3:-}" ] || die "usage: refusal-judge.sh --judge <report.json> <worker-lines.txt>"
    REPORT="$(jq -c . "$2")" || die "$2 is not JSON"
    HOST_LINES="$(cat "$3")"
    GRANTED_VALUE="${DEMO_JUDGE_GRANTED_VALUE:-}"
    JOB_ID="${DEMO_JUDGE_JOB_ID:-(judged)}"
    COUNT_BEFORE="${DEMO_JUDGE_COUNT_BEFORE:-}"; COUNT_AFTER="${DEMO_JUDGE_COUNT_AFTER:-}"
    COUNTER_NAME="${DEMO_JUDGE_COUNTER:-}"; FIFTH="${DEMO_JUDGE_FIFTH:-1}"
    LIVE_RC="${DEMO_JUDGE_LIVE_RC:-}"; ENDED_RC="${DEMO_JUDGE_ENDED_RC:-}"
    LIVE_OUT="${DEMO_JUDGE_LIVE_OUT:-SERVED: \"left here by the operator\"}"; ENDED_OUT="${DEMO_JUDGE_ENDED_OUT:-refused: (Unauthorized)}"
    if [ -n "$LIVE_RC" ] && [ -n "$ENDED_RC" ]; then OUTSIDE=1; OUTSIDE_WHY=""; else OUTSIDE=0; OUTSIDE_WHY="no probe result was given to judge"; fi
    if [ "$FIFTH" = 1 ] && [ "$OUTSIDE" = 0 ] && [ "${AEGIX_DEMO_REQUIRE_ALL:-0}" = "1" ]; then
        die "AEGIX_DEMO_REQUIRE_ALL=1 and the fifth attempt cannot be made: $OUTSIDE_WHY"
    fi
    judge
    [ "$FAILURES" = 0 ] || { red "▶ $FAILURES check(s) FAILED"; exit 1; }
    if [ "$FIFTH" = 1 ]; then of=5; else of=4; fi
    green "▶ Both controls served; $SHOWN of $of attempts made, every one refused."
    exit 0
fi
