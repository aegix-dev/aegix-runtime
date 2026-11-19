#!/usr/bin/env bash
# The refusal demo against the REFERENCE CONTROLLER: a message bus, the
# reference controller (aegix-reference-controller) and one unmodified worker,
# all on this machine, with no database and no platform controller.
#
#   scripts/reference-controller-demo.sh                     the development posture
#   scripts/reference-controller-demo.sh --posture worker-identity
#   scripts/reference-controller-demo.sh --posture both      one build, then each in turn
#   scripts/reference-controller-demo.sh --keep              leave the run directory
#   scripts/reference-controller-demo.sh --no-build          use the binaries as built
#
# What it shows, in order:
#
#   A. The hostile module (scripts/demo/hostile-module.rs) is dispatched to
#      the worker. Its two controls are served and its four attempts refused,
#      and scripts/demo/refusal-judge.sh decides that: the one table of the
#      attempts, and the one judgement, for every run of this module.
#   B. A request from outside the module that names the module's job. Under
#      `fleet-key` it is signed with the key every worker on such a stack
#      holds: served while the job runs, refused once it has ended. Under
#      `worker-identity` the controller holds no such key: the same request is
#      refused at admission while the job runs, and a second pinned worker's
#      request for a job it did not claim is refused too.
#   C. A dispatch that waited too long. The worker is stopped, a job is sent
#      with a five-second pickup window, and the worker is let go after it.
#      The worker refuses to start the job, the module never runs, and a
#      request that names the job is refused.
#   D. A job the controller gave up on. The worker is stopped while the
#      module runs. The controller's wait ends, it records the job as timed
#      out and tells the workers to stop it. The worker is let go: from then
#      on a request that names the job is refused, and the record stays
#      `timeout` whatever the worker sends afterwards.
#
# It builds what it runs from this checkout (the worker, the reference
# controller, the probe, and the module through the platform's own compile
# path), so it needs cargo, cargo-component and the wasm32-wasip2 target, and
# jq, python3, uuidgen and a nats-server on PATH (AEGIX_DEMO_NATS_SERVER names
# another).
# Every key and password is minted here, into a directory only this user can
# read, and removed with it. Nothing is printed that is a secret.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
POSTURE="fleet-key"; KEEP=0; BUILD=1
while [ $# -gt 0 ]; do
    case "$1" in
        --posture) POSTURE="${2:-}"; shift 2 ;;
        --keep) KEEP=1; shift ;;
        --no-build) BUILD=0; shift ;;
        -h|--help) sed -n '2,40p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) printf 'unknown argument: %s\n' "$1" >&2; exit 2 ;;
    esac
done
case "$POSTURE" in fleet-key|worker-identity|both) ;; *) printf -- '--posture is fleet-key, worker-identity or both\n' >&2; exit 2 ;; esac

TARGET_DIR="${CARGO_TARGET_DIR:-$REPO_ROOT/target}"
CTL_BIN="${AEGIX_DEMO_CONTROLLER_BIN:-$TARGET_DIR/debug/aegix-reference-controller}"
WRK_BIN="${AEGIX_DEMO_WORKER_BIN:-$TARGET_DIR/debug/worker}"
PROBE_BIN="${AEGIX_DEMO_PROBE_BIN:-$TARGET_DIR/debug/aegix-e2e-probe}"
NATS_BIN="${AEGIX_DEMO_NATS_SERVER:-nats-server}"
MODULE_SRC="$REPO_ROOT/scripts/demo/hostile-module.rs"
BOOT_TIMEOUT="${AEGIX_DEMO_BOOT_TIMEOUT:-120}"
HOLD_SECS=90          # how long the module waits to be released (it caps this at 120)
PICKUP_WINDOW=5       # part C: seconds after signing in which a worker may start a job
GRANTED_VALUE="value-of-the-granted-demo-secret"

red()    { printf '\033[1;31m%s\033[0m\n' "$*" >&2; }
green()  { printf '\033[1;32m%s\033[0m\n' "$*"; }
dim()    { printf '\033[2m%s\033[0m\n' "$*"; }
bold()   { printf '\033[1m%s\033[0m\n' "$*"; }
step()   { printf '\n\033[1;36m▶ %s\033[0m\n' "$*"; }

RUN=""; NATS_PID=""; CTL_PID=""; WRK_PID=""; FAILURES=0
stop_process() { # stop_process <pid>
    [ -n "${1:-}" ] || return 0
    kill -CONT "$1" 2>/dev/null || true
    kill "$1" 2>/dev/null || true
    wait "$1" 2>/dev/null || true
}
# Every exit goes through here: an EXIT trap alone would turn a crash into 0.
finish() { # finish <status>
    trap - EXIT INT TERM
    stop_process "$WRK_PID"; stop_process "$CTL_PID"; stop_process "$NATS_PID"
    if [ -n "$RUN" ] && [ -d "$RUN" ]; then
        if [ "$KEEP" = 1 ] || { [ "$1" != 0 ] && [ "${AEGIX_DEMO_KEEP_ON_FAILURE:-0}" = 1 ]; }; then
            dim "run directory kept: $RUN (it holds this run's keys; remove it when done)"
        else
            rm -rf "$RUN"
        fi
    fi
    exit "$1"
}
die()  { red "✗ $*"; finish 1; }
fail() { red "     ✗ $*"; FAILURES=$(( FAILURES + 1 )); }
trap 'finish 1' INT TERM
trap 'red "✗ the script stopped at line $LINENO"; finish 1' ERR
need() { command -v "$1" >/dev/null 2>&1 || die "missing required tool: $1"; }
show_log() { # show_log <file>: the last lines of a process that failed
    [ -r "$1" ] && tail -15 "$1" | cut -c1-300 >&2 || true
}

need jq; need python3; need uuidgen
command -v "$NATS_BIN" >/dev/null 2>&1 || die "no nats-server on PATH (brew install nats-server), or name one with AEGIX_DEMO_NATS_SERVER"

# ── 0. Build ────────────────────────────────────────────────────────────────
if [ "$BUILD" = 1 ]; then
    step "0. build the worker, the reference controller and the probe from this checkout"
    ( cd "$REPO_ROOT" && cargo build --workspace --bin worker --bin aegix-reference-controller --bin aegix-e2e-probe ) \
        || die "the build failed"
fi
for bin in "$CTL_BIN" "$WRK_BIN" "$PROBE_BIN"; do
    [ -x "$bin" ] || die "$bin is not built (run without --no-build)"
done

umask 077
RUN="$(mktemp -d "${TMPDIR:-/tmp}/talos-refctl.XXXXXX")"
mkdir -p "$RUN/logs" "$RUN/keys" "$RUN/control"
CTL_LOG="$RUN/logs/controller.log"; WRK_LOG="$RUN/logs/worker.log"; NATS_LOG="$RUN/logs/nats.log"

compile_module() { # compile_module <out.wasm> <log>
    ( cd "$REPO_ROOT" && cargo run --quiet -p aegix-compilation --example compile_module -- "$MODULE_SRC" agent-node "$1" ) >"$2" 2>&1 \
        || { show_log "$2"; die "the module did not compile"; }
}

# `both`: build and compile once, then run each posture as its own process
# with its own keys and directory.
if [ "$POSTURE" = both ]; then
    WASM="${AEGIX_DEMO_HOSTILE_WASM:-}"
    if [ -z "$WASM" ]; then
        step "0b. compile the hostile module through the platform's compile path (agent-node)"
        WASM="$RUN/hostile.wasm"
        compile_module "$WASM" "$RUN/logs/compile.log"
    fi
    keep=(); [ "$KEEP" = 0 ] || keep=( --keep )
    for posture in fleet-key worker-identity; do
        AEGIX_DEMO_HOSTILE_WASM="$WASM" bash "${BASH_SOURCE[0]}" --no-build --posture "$posture" ${keep[@]+"${keep[@]}"} \
            || { red "▶ posture $posture FAILED"; finish 1; }
    done
    finish 0
fi

WASM="${AEGIX_DEMO_HOSTILE_WASM:-}"
if [ -z "$WASM" ]; then
    step "0b. compile the hostile module through the platform's compile path (agent-node)"
    WASM="$RUN/hostile.wasm"
    compile_module "$WASM" "$RUN/logs/compile.log"
else
    [ -r "$WASM" ] || die "AEGIX_DEMO_HOSTILE_WASM=$WASM is not readable"
    cp "$WASM" "$RUN/hostile.wasm"; WASM="$RUN/hostile.wasm"
fi
dim "module: $(wc -c <"$WASM" | tr -d ' ') bytes"

# ── 1. Keys, passwords and the configuration ───────────────────────────────
step "1. mint this run's keys and write the configuration ($POSTURE)"
free_port() { python3 -I -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'; }
hex32() { od -An -tx1 -N32 /dev/urandom | tr -d ' \n'; }
NATS_PORT="$(free_port)"; METRICS_PORT="$(free_port)"
NATS_CTL_PASSWORD="$(bash "$REPO_ROOT/scripts/nats-password.sh")"
NATS_WRK_PASSWORD="$(bash "$REPO_ROOT/scripts/nats-password.sh")"
printf '%s\n' "$NATS_CTL_PASSWORD" >"$RUN/keys/nats-controller.password"
printf '%s\n' "$NATS_WRK_PASSWORD" >"$RUN/keys/nats-worker.password"
# The worker always holds a WORKER_SHARED_KEY (it derives its checkpoint and
# cache keys from it). Under `fleet-key` the controller holds the same one.
# Under `worker-identity` the controller never sees it.
hex32 >"$RUN/keys/worker-shared.key"
AOT_KEY="$(hex32)"; METRICS_TOKEN="$(hex32)"
ACTOR_ID="$(uuidgen | tr 'A-Z' 'a-z')"

jq -n --arg g "$GRANTED_VALUE" '{"demo/granted": $g, "demo/not-granted": "stored, and granted to no module"}' >"$RUN/secrets.json"
jq -n --arg posture "$POSTURE" --arg actor "$ACTOR_ID" --argjson pickup "$PICKUP_WINDOW" '{
    posture: $posture,
    secrets_file: "secrets.json",
    pickup_window_secs: $pickup,
    actors: [{
        name: "demo", id: $actor,
        max_llm_tier: "tier1", egress_scope: "public", max_write_ceiling: "readonly",
        memory: {"demo/readable": "left here by the operator"}
    }],
    modules: [
        { name: "hostile", wasm: "hostile.wasm", capability_world: "agent-node",
          allowed_hosts: ["api.anthropic.com"], allowed_methods: ["GET"], allowed_secrets: ["demo/granted"],
          max_fuel: 50000000, timeout_secs: 150 },
        { name: "hostile-short", wasm: "hostile.wasm", capability_world: "agent-node",
          allowed_hosts: ["api.anthropic.com"], allowed_methods: ["GET"], allowed_secrets: ["demo/granted"],
          max_fuel: 50000000, timeout_secs: 10 }
    ]
}' >"$RUN/controller.json"

CTL_ENV=(); WRK_ENV=()
if [ "$POSTURE" = fleet-key ]; then
    CTL_ENV+=( "WORKER_SHARED_KEY_FILE=$RUN/keys/worker-shared.key" )
else
    # Two pinned workers: `demo-worker-a` runs; `demo-worker-b` is the identity
    # the probe asks as. The controller's keygen writes each pair.
    "$CTL_BIN" keygen --out-dir "$RUN/keys/a" --worker-id demo-worker-a >"$RUN/keys/a.env"
    "$CTL_BIN" keygen --out-dir "$RUN/keys/b" --worker-id demo-worker-b >"$RUN/keys/b.env"
    CONTROLLER_PUBLIC_KEY="$(cat "$RUN/keys/a/controller.pub")"
    PINS="demo-worker-a=$(cat "$RUN/keys/a/worker.pub"),demo-worker-b=$(cat "$RUN/keys/b/worker.pub")"
    CTL_ENV+=( "AEGIX_CONTROLLER_SIGNING_KEY_FILE=$RUN/keys/a/controller.key" "AEGIX_WORKER_PUBLIC_KEYS=$PINS" )
    WRK_ENV+=( "AEGIX_WORKER_ID=demo-worker-a" "AEGIX_WORKER_SIGNING_KEY_FILE=$RUN/keys/a/worker.key"
               "AEGIX_CONTROLLER_PUBLIC_KEY=$CONTROLLER_PUBLIC_KEY"
               "AEGIX_ENVELOPE_SEALING=required" "AEGIX_DISPATCH_REQUIRE_ED25519=1" )
fi

# ── 2. The bus, the controller, the worker ─────────────────────────────────
step "2. start nats-server (127.0.0.1:$NATS_PORT), the reference controller and one worker"
(
    cd "$REPO_ROOT/deploy/nats" && exec env -i PATH="$PATH" HOME="$HOME" \
        NATS_USER=talos-controller NATS_PASSWORD="$NATS_CTL_PASSWORD" \
        NATS_WORKER_USER=talos-worker NATS_WORKER_PASSWORD="$NATS_WRK_PASSWORD" \
        "$NATS_BIN" -a 127.0.0.1 -p "$NATS_PORT" -c nats-shared-worker.conf >"$NATS_LOG" 2>&1
) &
NATS_PID=$!
deadline=$(( $(date +%s) + 20 ))
until grep -q "Server is ready" "$NATS_LOG" 2>/dev/null; do
    kill -0 "$NATS_PID" 2>/dev/null || { show_log "$NATS_LOG"; die "nats-server exited"; }
    [ "$(date +%s)" -lt "$deadline" ] || die "nats-server was not ready in 20s"
    sleep 0.2
done

(
    cd "$RUN" && exec env -i PATH="$PATH" HOME="$HOME" TMPDIR="${TMPDIR:-/tmp}" \
        RUST_ENV=development RUST_LOG="${AEGIX_DEMO_RUST_LOG:-info}" \
        NATS_URL="nats://127.0.0.1:${NATS_PORT}" NATS_USER=talos-controller \
        NATS_PASSWORD_FILE="$RUN/keys/nats-controller.password" \
        ${CTL_ENV[@]+"${CTL_ENV[@]}"} \
        "$CTL_BIN" serve --config "$RUN/controller.json" --control-dir "$RUN/control" >"$CTL_LOG" 2>&1
) &
CTL_PID=$!
rc() { "$CTL_BIN" "$@" --control-dir "$RUN/control"; }
deadline=$(( $(date +%s) + BOOT_TIMEOUT ))
until rc status >/dev/null 2>&1; do
    kill -0 "$CTL_PID" 2>/dev/null || { show_log "$CTL_LOG"; die "the reference controller exited before it served"; }
    [ "$(date +%s)" -lt "$deadline" ] || die "the reference controller did not serve in ${BOOT_TIMEOUT}s"
    sleep 0.3
done

(
    cd "$RUN" && exec env -i PATH="$PATH" HOME="$HOME" TMPDIR="${TMPDIR:-/tmp}" \
        RUST_ENV=development RUST_LOG="${AEGIX_DEMO_RUST_LOG:-info}" \
        NATS_URL="nats://127.0.0.1:${NATS_PORT}" NATS_USER=talos-worker NATS_PASSWORD="$NATS_WRK_PASSWORD" \
        WORKER_SHARED_KEY="$(cat "$RUN/keys/worker-shared.key")" AEGIX_AOT_HMAC_KEY="$AOT_KEY" \
        AEGIX_WRITE_CEILING_ENFORCED=1 AEGIX_DISABLE_POOLING=true \
        METRICS_PORT="$METRICS_PORT" METRICS_AUTH_TOKENS="$METRICS_TOKEN" \
        ${WRK_ENV[@]+"${WRK_ENV[@]}"} \
        "$WRK_BIN" >"$WRK_LOG" 2>&1
) &
WRK_PID=$!
deadline=$(( $(date +%s) + BOOT_TIMEOUT ))
until grep -q "Subscribed to 'talos.jobs' queue" "$WRK_LOG" 2>/dev/null; do
    kill -0 "$WRK_PID" 2>/dev/null || { show_log "$WRK_LOG"; die "the worker exited before it subscribed"; }
    [ "$(date +%s)" -lt "$deadline" ] || { show_log "$WRK_LOG"; die "the worker did not subscribe to the job queue in ${BOOT_TIMEOUT}s"; }
    sleep 0.5
done
dim "controller: $(rc status | jq -c '{posture, modules, secrets: (.secret_paths | length)}' 2>/dev/null || true)"

# The controller's count of memory calls it refused: for one reason under one
# decision, or every reason under it.
counter() { # counter <decision> [<reason>]
    rc counters | jq -r --arg d "$1" --arg r "${2:-}" \
        '.refusals[$d]["talos.memory.op"] // {} | if $r == "" then ([.[]] | add // 0) else (.[$r] // 0) end'
}
# A request from outside the module, as the shared worker NATS user.
#   probe_fleet <job>        signed with the worker's fleet key
#   probe_worker <a|b> <job> signed with demo-worker-a's or -b's own key
PROBE_OUT=""; PROBE_RC=0
probe_fleet() {
    PROBE_RC=0
    PROBE_OUT="$(WORKER_SHARED_KEY_FILE="$RUN/keys/worker-shared.key" "$PROBE_BIN" fleet-memory-get \
        --nats "nats://127.0.0.1:${NATS_PORT}" --nats-user talos-worker --nats-password-file "$RUN/keys/nats-worker.password" \
        --actor "$ACTOR_ID" --execution "$1" --job "$1" --key demo/readable 2>&1)" || PROBE_RC=$?
}
probe_worker() {
    PROBE_RC=0
    PROBE_OUT="$("$PROBE_BIN" memory-get \
        --nats "nats://127.0.0.1:${NATS_PORT}" --nats-user talos-worker --nats-password-file "$RUN/keys/nats-worker.password" \
        --worker-id "demo-worker-$1" --key-file "$RUN/keys/$1/worker.key" \
        --actor "$ACTOR_ID" --execution "$2" --job "$2" --key demo/readable 2>&1)" || PROBE_RC=$?
}
job_field() { rc job --job "$1" 2>/dev/null | jq -r "$2" || true; }
where_gate() { printf 'aegix-rpc-gates/src/dispatch_binding.rs:%s' "$(grep -n -m1 'pub async fn gate' "$REPO_ROOT/aegix-rpc-gates/src/dispatch_binding.rs" | cut -d: -f1)"; }

# ── A. The hostile module ──────────────────────────────────────────────────
step "A. dispatch the hostile module; it holds its job open for up to ${HOLD_SECS}s"
answer="$(rc dispatch --module hostile --actor demo --input "$(jq -cn --argjson h "$HOLD_SECS" '{config:{HOLD_SECS:$h}}')")" \
    || die "the dispatch was refused: $answer"
JOB_ID="$(printf '%s' "$answer" | jq -r '.job_id // empty')"
[ -n "$JOB_ID" ] || die "the dispatch answer names no job: $answer"
# The module has made its attempts once the worker has refused its write.
deadline=$(( $(date +%s) + 60 ))
until grep -q "write-ceiling" "$WRK_LOG" 2>/dev/null; do
    [ "$(job_field "$JOB_ID" '.ended')" != true ] || die "the job ended before it could be probed: $(rc job --job "$JOB_ID" | jq -c '.job | {state, error: .outcome.error}')"
    [ "$(date +%s)" -lt "$deadline" ] || { show_log "$WRK_LOG"; die "the module did not reach its hold in 60s"; }
    sleep 0.5
done
dim "job $JOB_ID is running and holding"

# ── B. A request from outside, while the job runs and after ────────────────
step "B. ask for the job's actor's data from outside the module"
NOT_LIVE_BEFORE="$(counter dispatch_binding not_live)"
ADMISSION_BEFORE="$(counter admission)"
probe_fleet "$JOB_ID"; LIVE_RC="$PROBE_RC"; LIVE_OUT="$PROBE_OUT"
if [ "$POSTURE" = worker-identity ]; then
    probe_worker b "$JOB_ID"; OTHER_RC="$PROBE_RC"; OTHER_OUT="$PROBE_OUT"
    NOT_LIVE_OTHER="$(counter dispatch_binding not_live)"
fi
rc remember --actor demo --key demo/release --value '"go"' --type working >/dev/null || die "could not release the module"
rc wait --job "$JOB_ID" --timeout-secs 150 >"$RUN/job.json" || true
STATE="$(jq -r '.job.state // empty' "$RUN/job.json")"
[ "$STATE" = completed ] || { show_log "$WRK_LOG"; die "the hostile module's job ended as '${STATE:-unknown}': $(jq -c '.job.outcome.error // .' "$RUN/job.json" | cut -c1-400)"; }
sleep 3   # the gate remembers a live job for two seconds
probe_fleet "$JOB_ID"; ENDED_RC="$PROBE_RC"; ENDED_OUT="$PROBE_OUT"
NOT_LIVE_AFTER="$(counter dispatch_binding not_live)"
ADMISSION_AFTER="$(counter admission)"

jq -c '.job.outcome.output' "$RUN/job.json" >"$RUN/report.json"
jq -r '.job.outcome.log_lines[]? | select(startswith("[host:"))' "$RUN/job.json" >"$RUN/host-lines.txt"

export DEMO_JUDGE_GRANTED_VALUE="$GRANTED_VALUE" DEMO_JUDGE_JOB_ID="$JOB_ID"
if [ "$POSTURE" = fleet-key ]; then
    DEMO_JUDGE_LIVE_RC="$LIVE_RC" DEMO_JUDGE_ENDED_RC="$ENDED_RC" DEMO_JUDGE_LIVE_OUT="$LIVE_OUT" DEMO_JUDGE_ENDED_OUT="$ENDED_OUT" \
    DEMO_JUDGE_COUNT_BEFORE="$NOT_LIVE_BEFORE" DEMO_JUDGE_COUNT_AFTER="$NOT_LIVE_AFTER" \
    DEMO_JUDGE_COUNTER='reference controller, refusals.dispatch_binding["talos.memory.op"].not_live' \
        bash "$REPO_ROOT/scripts/demo/refusal-judge.sh" --judge "$RUN/report.json" "$RUN/host-lines.txt" || FAILURES=$(( FAILURES + 1 ))
else
    DEMO_JUDGE_FIFTH=0 bash "$REPO_ROOT/scripts/demo/refusal-judge.sh" --judge "$RUN/report.json" "$RUN/host-lines.txt" || FAILURES=$(( FAILURES + 1 ))
    printf '\n'
    bold "What a holder of the worker's shared key, and a second pinned worker, were given"
    printf '\n  \033[1m%s\033[0m\n' "ask with the fleet key, while the job runs and after"
    printf '     %-10s %s\n' "asked" "talos.memory.op Get \"demo/readable\", signed with the worker's WORKER_SHARED_KEY, bound to job $JOB_ID"
    printf '     %-10s %s\n' "job live" "$(printf '%s' "$LIVE_OUT" | tail -1 | cut -c1-160)"
    printf '     %-10s %s\n' "job ended" "$(printf '%s' "$ENDED_OUT" | tail -1 | cut -c1-160)"
    printf '     %-10s %s\n' "controller" "refusals.admission[\"talos.memory.op\"]: $ADMISSION_BEFORE → $ADMISSION_AFTER ($(rc counters | jq -c '.refusals.admission["talos.memory.op"] // {}'))"
    if [ "$LIVE_RC" = 0 ] && [ "$ENDED_RC" = 0 ] && [ "$ADMISSION_AFTER" -ge $(( ADMISSION_BEFORE + 2 )) ]; then
        green "     ✓ refused both times, at admission: this controller holds no fleet key to believe"
    else
        fail "a fleet-key request was not refused at admission both times (exits $LIVE_RC, $ENDED_RC; count $ADMISSION_BEFORE → $ADMISSION_AFTER)"
    fi
    printf '\n  \033[1m%s\033[0m\n' "ask as another pinned worker, for a job it did not claim"
    printf '     %-10s %s\n' "asked" "the same Get, signed by demo-worker-b with its own key, bound to demo-worker-a's job, while it ran"
    printf '     %-10s %s\n' "given" "$(printf '%s' "$OTHER_OUT" | tail -1 | cut -c1-160)"
    CLAIMED_BY="$(jq -r '.job.claimed_by // empty' "$RUN/job.json")"
    printf '     %-10s %s\n' "controller" "the job's secrets were claimed by ${CLAIMED_BY:-nobody}; refusals.dispatch_binding[\"talos.memory.op\"].not_live: $NOT_LIVE_BEFORE → $NOT_LIVE_OTHER"
    if [ "$OTHER_RC" != 0 ]; then
        fail "demo-worker-b was not refused demo-worker-a's job (probe exit $OTHER_RC)"
    elif [ "$CLAIMED_BY" != demo-worker-a ]; then
        fail "the job's record does not say demo-worker-a claimed it (it says '${CLAIMED_BY:-nobody}'): the secrets did not travel sealed to one worker"
    elif [ "$NOT_LIVE_OTHER" = "$NOT_LIVE_BEFORE" ]; then
        fail "refused, but not by the dispatch-binding gate: its count did not move"
    else
        green "     ✓ refused: a job's data is served to the worker that claimed it"
    fi
fi

# ── C. A dispatch that waited too long ─────────────────────────────────────
step "C. stop the worker, dispatch with a ${PICKUP_WINDOW}s pickup window, let the worker go after it"
kill -STOP "$WRK_PID"
answer="$(rc dispatch --module hostile-short --actor demo --input '{"config":{"HOLD_SECS":0}}')" || die "the dispatch was refused: $answer"
LATE_JOB="$(printf '%s' "$answer" | jq -r '.job_id // empty')"
[ -n "$LATE_JOB" ] || die "the dispatch answer names no job: $answer"
sleep $(( PICKUP_WINDOW + 3 ))
kill -CONT "$WRK_PID"
rc wait --job "$LATE_JOB" --timeout-secs 60 >"$RUN/late.json" || true
LATE_STATE="$(jq -r '.job.state // empty' "$RUN/late.json")"
LATE_ERROR="$(jq -r '.job.outcome.error // empty' "$RUN/late.json")"
sleep 3
# Asked with a key the controller believes, so a refusal is the gate's: the
# fleet key, or the key of the one worker this run starts (which is the
# worker that claims every job here).
outside() { if [ "$POSTURE" = fleet-key ]; then probe_fleet "$1"; else probe_worker a "$1"; fi; }
outside "$LATE_JOB"; LATE_RC="$PROBE_RC"
printf '\n  \033[1m%s\033[0m\n' "start a job after its deadline"
printf '     %-10s %s\n' "sent" "job $LATE_JOB, signed with a start deadline ${PICKUP_WINDOW}s out; the worker was stopped for $(( PICKUP_WINDOW + 3 ))s"
printf '     %-10s %s\n' "worker" "received it after the deadline and answered: ${LATE_ERROR:-(nothing)}"
printf '     %-10s %s\n' "job" "${LATE_STATE:-unknown}${LATE_ERROR:+: $LATE_ERROR}"
printf '     %-10s %s\n' "decided in" "worker/src/job_execution.rs:$(grep -n -m1 'job deadline expired' "$REPO_ROOT/worker/src/job_execution.rs" | cut -d: -f1), on the deadline aegix-reference-controller/src/dispatch.rs signs"
if [ "$LATE_STATE" = completed ]; then
    fail "NOT REFUSED: the job ran after its deadline"
elif [ -z "$LATE_STATE" ] || [ "$(jq -r '.ended' "$RUN/late.json")" != true ]; then
    fail "the job has not ended: $(jq -c . "$RUN/late.json" | cut -c1-300)"
elif [ "$(jq -r '.job.outcome.output | (.steps? // []) | length' "$RUN/late.json")" != 0 ]; then
    fail "the module ran: its report has steps"
elif ! grep -qi "deadline" <<<"$LATE_ERROR"; then
    fail "the job ended as $LATE_STATE, but not on its deadline: ${LATE_ERROR:-no error recorded}"
elif [ "$LATE_RC" != 0 ]; then
    fail "a request that names the ended job was not refused (probe exit $LATE_RC)"
else
    green "     ✓ the worker refused to start it, the module never ran, and a request that names the job is refused"
fi

# ── D. A job the controller gave up on ─────────────────────────────────────
SHORT_WAIT=$(( PICKUP_WINDOW + 10 + 10 ))   # pickup window + the module's time limit + the result's grace
step "D. stop the worker while the module runs; the controller's wait ends after ${SHORT_WAIT}s"
# Part B left the release in the actor's memory; without removing it this
# module would be released the moment it looked.
rc forget --actor demo --key demo/release >/dev/null || die "could not remove the release left by part B"
REFUSED_WRITES="$(grep -c "write-ceiling" "$WRK_LOG" || true)"
answer="$(rc dispatch --module hostile-short --actor demo --input '{"config":{"HOLD_SECS":120}}')" || die "the dispatch was refused: $answer"
STALLED_JOB="$(printf '%s' "$answer" | jq -r '.job_id // empty')"
[ -n "$STALLED_JOB" ] || die "the dispatch answer names no job: $answer"
deadline=$(( $(date +%s) + 30 ))
until [ "$(grep -c "write-ceiling" "$WRK_LOG" || true)" -gt "$REFUSED_WRITES" ]; do
    [ "$(date +%s)" -lt "$deadline" ] || { show_log "$WRK_LOG"; die "the module did not start in 30s"; }
    sleep 0.3
done
kill -STOP "$WRK_PID"
outside "$STALLED_JOB"; RUNNING_RC="$PROBE_RC"
NOT_LIVE_STALLED="$(counter dispatch_binding not_live)"
rc wait --job "$STALLED_JOB" --timeout-secs $(( SHORT_WAIT + 30 )) >"$RUN/stalled.json" || true
STALLED_STATE="$(jq -r '.job.state // empty' "$RUN/stalled.json")"
kill -CONT "$WRK_PID"
sleep 5   # the worker runs again: its own time limit ends the module, and it answers
outside "$STALLED_JOB"; GAVE_UP_RC="$PROBE_RC"
STALLED_LATER="$(job_field "$STALLED_JOB" '.job.state')"
printf '\n  \033[1m%s\033[0m\n' "use a job after its controller gave up on it"
printf '     %-10s %s\n' "sent" "job $STALLED_JOB; the worker was stopped while its module ran"
printf '     %-10s %s\n' "job live" "a request that names it: $([ "$RUNNING_RC" = 2 ] && printf 'served' || printf 'exit %s' "$RUNNING_RC")"
printf '     %-10s %s\n' "controller" "recorded it as ${STALLED_STATE:-unknown}: $(jq -r '.job.outcome.error // empty' "$RUN/stalled.json" | cut -c1-160)"
printf '     %-10s %s\n' "after" "the worker ran again for 5s; a request that names the job: $([ "$GAVE_UP_RC" = 0 ] && printf 'refused' || printf 'exit %s' "$GAVE_UP_RC"); the record: ${STALLED_LATER:-unknown}"
printf '     %-10s %s\n' "controller" "refusals.dispatch_binding[\"talos.memory.op\"].not_live: $NOT_LIVE_STALLED → $(counter dispatch_binding not_live)"
printf '     %-10s %s\n' "decided in" "aegix-reference-controller/src/serve.rs:$(grep -n -m1 'async fn await_result' "$REPO_ROOT/aegix-reference-controller/src/serve.rs" | cut -d: -f1), then $(where_gate)"
if [ "$RUNNING_RC" != 2 ]; then
    fail "while the job ran the request was not served (probe exit $RUNNING_RC): the refusal after cannot be told from one that is always made"
elif [ "$STALLED_STATE" != timeout ]; then
    fail "the controller did not record the job as timed out: ${STALLED_STATE:-unknown}"
elif [ "$GAVE_UP_RC" != 0 ]; then
    fail "NOT REFUSED: a request that names the job was served after the controller gave up on it (probe exit $GAVE_UP_RC)"
elif [ "$STALLED_LATER" != timeout ]; then
    fail "the record changed after the controller gave up: it now says ${STALLED_LATER:-unknown}"
else
    green "     ✓ timed out by the controller, refused from then on, and nothing the worker sent later changed the record"
fi

printf '\n'
if [ "$FAILURES" != 0 ]; then
    red "▶ $FAILURES check(s) FAILED ($POSTURE)"
    show_log "$CTL_LOG"
    finish 1
fi
green "▶ Reference controller, posture $POSTURE: the controls were served and every attempt was refused."
finish 0
