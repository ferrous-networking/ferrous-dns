#!/usr/bin/env bash
# =============================================================================
# ferrous-dns — Performance Benchmark vs. Competitors
# =============================================================================
# Measures QPS, latency and loss across three scenarios:
#
#   A  cache on, blocking off, query log off   theoretical ceiling
#   B  cache on, blocking on,  query log off   cost of the blocking engine
#   C  cache on, blocking on,  query log on    what a user actually runs
#
# Scenario A runs all six servers. Scenarios B and C run only the three that
# have a blocking engine (ferrous-dns, Blocky, AdGuard Home): Unbound and
# PowerDNS Recursor have none, and loading 1M rules into Pi-hole means driving
# a gravity import, which is slow and brittle enough that it would become the
# thing under test.
#
# The workload is generated, not checked in — see generate-queries.py and
# generate-blocklist.py. Both are deterministic given --seed, so a published
# number can be reproduced from the repository alone.
#
# Prerequisites:
#   - dnsperf (DNS-OARC):  apt install dnsperf | pacman -S dnsperf
#   - dig (bind-tools), python3, docker + docker compose
#   - taskset (util-linux) — optional; enables CPU isolation on Linux so the
#     load generator and server-under-test don't contend for cores
#   - A ferrous-dns release binary at target/release/ferrous-dns (the bench
#     image copies it in) — see --help for the build line.
#
# Usage:
#   ./bench/benchmark.sh [options]
#
# Options:
#   --scenario <A|B|C|all>  Scenario(s) to run (default: A)
#   --profile  <quick|publish>
#                           quick   = 10s x 3 runs  (~5.5 min for scenario A)
#                           publish = 30s x 5 runs  (~17 min for scenario A)
#   --duration <s>          Override the profile's per-run duration
#   --runs     <n>          Override the profile's run count
#   --warmup   <s>          Override the profile's warm-up duration
#   --clients  <n>          Concurrent dnsperf clients (default: 10)
#   --ferrous  <addr>       ferrous-dns address (default: 127.0.0.1:5353)
#   --regen                 Regenerate the query set and blocklist before running
#   --no-docker             Skip starting competitor containers
#   --output   <file>       Markdown report path (default: bench/benchmark-results.md)
#   --help                  Show this help
#
# Build line used for published numbers:
#   RUSTFLAGS="-C target-cpu=native" cargo build --release -p ferrous-dns
#   docker compose -f bench/docker-compose.yml build ferrous-dns
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
DATA_DIR="$SCRIPT_DIR/data"
RUN_DIR="$SCRIPT_DIR/.run"
RAW_DIR="$RUN_DIR/raw"
RESULTS_DIR="$SCRIPT_DIR/results"
DOCKER_COMPOSE="$SCRIPT_DIR/docker-compose.yml"

# ── defaults ────────────────────────────────────────────────────────────────
SCENARIO_ARG="A"
PROFILE="quick"
DURATION=""
RUNS=""
WARMUP=""
CLIENTS=${CLIENTS:-10}
FERROUS_ADDR=${FERROUS_DNS_ADDR:-"127.0.0.1:5353"}
USE_DOCKER=true
REGEN=false
OUTPUT_FILE="$SCRIPT_DIR/benchmark-results.md"

QUERIES_FILE="$DATA_DIR/queries-realistic.txt"
BLOCKLIST_URL="http://127.0.0.1:8081/blocklist.txt"
BLOCKLIST_ADVANCED_URL="http://127.0.0.1:8081/blocklist-advanced.txt"
FERROUS_API="http://127.0.0.1:9090/api"

# ── CPU isolation state (populated by setup_cpu_isolation) ───────────────────
# dnsperf and the server-under-test must not share cores, otherwise they fight
# for CPU and the kernel drops UDP on loopback — noise dnsperf mis-reports as
# "lost". TASKSET pins dnsperf to a dedicated core set.
PIN_ENABLED=false
LOADGEN_CPUS=""
declare -a TASKSET=()

# ── ports for competitor containers ─────────────────────────────────────────
PIHOLE_PORT=5354
ADGUARD_PORT=5359   # not 5355 — that's LLMNR, held by systemd-resolved on many hosts
UNBOUND_PORT=5356
BLOCKY_PORT=5357
POWERDNS_PORT=5358

# ── colour output ────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

log()  { echo -e "${CYAN}[bench]${RESET} $*" >&2; }
ok()   { echo -e "${GREEN}[  ok ]${RESET} $*" >&2; }
warn() { echo -e "${YELLOW}[ warn]${RESET} $*" >&2; }
err()  { echo -e "${RED}[error]${RESET} $*" >&2; }

# ── argument parsing ─────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case $1 in
    --scenario)  SCENARIO_ARG="$2"; shift 2 ;;
    --profile)   PROFILE="$2"; shift 2 ;;
    --duration)  DURATION="$2"; shift 2 ;;
    --runs)      RUNS="$2"; shift 2 ;;
    --warmup)    WARMUP="$2"; shift 2 ;;
    --clients)   CLIENTS="$2"; shift 2 ;;
    --ferrous)   FERROUS_ADDR="$2"; shift 2 ;;
    --regen)     REGEN=true; shift ;;
    --no-docker) USE_DOCKER=false; shift ;;
    --output)    OUTPUT_FILE="$2"; shift 2 ;;
    --help)
      sed -n '/^# Usage/,/^# =====/p' "$0" | head -n -1
      exit 0 ;;
    *) err "Unknown option: $1"; exit 1 ;;
  esac
done

case "$PROFILE" in
  quick)   : "${DURATION:=10}"; : "${RUNS:=3}"; : "${WARMUP:=20}" ;;
  publish) : "${DURATION:=30}"; : "${RUNS:=5}"; : "${WARMUP:=45}" ;;
  *) err "Unknown profile: $PROFILE (expected quick or publish)"; exit 1 ;;
esac

case "$SCENARIO_ARG" in
  all)     SCENARIOS=(A B C) ;;
  A|B|C)   SCENARIOS=("$SCENARIO_ARG") ;;
  *) err "Unknown scenario: $SCENARIO_ARG (expected A, B, C or all)"; exit 1 ;;
esac

# ── server registry ──────────────────────────────────────────────────────────
# key|compose service|display name|port
server_meta() {
  case "$1" in
    ferrous)  echo "ferrous-dns|🦀 ferrous-dns|${FERROUS_ADDR##*:}" ;;
    pihole)   echo "pihole|🕳️ Pi-hole|$PIHOLE_PORT" ;;
    adguard)  echo "adguard|🛡️ AdGuard Home|$ADGUARD_PORT" ;;
    unbound)  echo "unbound|⚡ Unbound (C)|$UNBOUND_PORT" ;;
    blocky)   echo "blocky|🔷 Blocky (Go)|$BLOCKY_PORT" ;;
    powerdns) echo "powerdns|⚡ PowerDNS (C++)|$POWERDNS_PORT" ;;
    *) err "Unknown server key: $1"; exit 1 ;;
  esac
}

scenario_servers() {
  case "$1" in
    A) echo "ferrous unbound powerdns blocky adguard pihole" ;;
    B|C) echo "ferrous blocky adguard" ;;
  esac
}

scenario_blocking()  { [[ "$1" == "A" ]] && echo false || echo true; }
scenario_querylog()  { [[ "$1" == "C" ]] && echo true  || echo false; }

# ── prerequisite checks ──────────────────────────────────────────────────────
check_prereqs() {
  local missing=false

  for tool in dnsperf dig python3 jq; do
    if ! command -v "$tool" &>/dev/null; then
      err "$tool not found — required"
      missing=true
    fi
  done

  if [[ "$USE_DOCKER" == "true" ]] && ! command -v docker &>/dev/null; then
    warn "docker not found — skipping competitor containers (--no-docker implied)"
    USE_DOCKER=false
  fi

  if [[ "$USE_DOCKER" == "true" && ! -x "$REPO_DIR/target/release/ferrous-dns" ]]; then
    warn "target/release/ferrous-dns missing — the bench image copies it in."
    warn "Build it first: RUSTFLAGS=\"-C target-cpu=native\" cargo build --release -p ferrous-dns"
  fi

  [[ "$missing" == "true" ]] && exit 1
  return 0
}

# ── workload generation ──────────────────────────────────────────────────────
ensure_datasets() {
  if [[ "$REGEN" == "true" || ! -f "$QUERIES_FILE" ]]; then
    log "Generating query set..."
    python3 "$SCRIPT_DIR/generate-queries.py" --out "$QUERIES_FILE"
  fi
  if [[ "$REGEN" == "true" || ! -f "$DATA_DIR/blocklist.txt" ]]; then
    log "Generating blocklist..."
    python3 "$SCRIPT_DIR/generate-blocklist.py" \
      --blocked-domains "$DATA_DIR/blocked-domains.txt" \
      --out-dir "$DATA_DIR"
  fi
}

# ── CPU isolation setup ──────────────────────────────────────────────────────
# Splits the host cores in half: the lower half runs the server-under-test
# (exported to docker-compose via BENCH_SERVER_CPUS / BENCH_SERVER_NCPU), the
# upper half runs dnsperf (via the TASKSET prefix).
setup_cpu_isolation() {
  local ncpu
  ncpu=$(nproc 2>/dev/null || echo 1)

  if [[ "$(uname -s)" != "Linux" ]] || ! command -v taskset &>/dev/null || [[ $ncpu -lt 4 ]]; then
    warn "CPU isolation disabled (needs Linux + taskset + ≥4 cores) — results may be noisy"
    return
  fi

  local half=$(( ncpu / 2 ))
  local server_cpus="0-$(( half - 1 ))"
  LOADGEN_CPUS="${half}-$(( ncpu - 1 ))"
  PIN_ENABLED=true
  TASKSET=(taskset -c "$LOADGEN_CPUS")

  export BENCH_SERVER_CPUS="$server_cpus"
  export BENCH_SERVER_NCPU="$half"
  # The stub upstream shares the load generator's cores: taking cycles from
  # dnsperf understates every server equally, taking them from the server under
  # test would not.
  export BENCH_LOADGEN_CPUS="$LOADGEN_CPUS"

  log "CPU isolation: server on cores ${server_cpus}, dnsperf on cores ${LOADGEN_CPUS}"
}

# ── scenario configuration rendering ─────────────────────────────────────────
# ferrous-dns has no environment overrides for these two knobs (entrypoint.sh
# only maps ports/paths, and there is no CLI subcommand), so the scenario config
# is rendered from the tracked base file. The awk pass is section-aware because
# `enabled = false` appears under five different tables.
render_ferrous_config() {
  local blocking="$1" querylog="$2" out="$3"
  awk -v blk="$blocking" -v lq="$querylog" '
    /^\[/ { section = $0 }
    section == "[blocking]" && /^enabled[[:space:]]*=/ {
      sub(/=[[:space:]]*(true|false)/, "= " blk)
    }
    section == "[database]" && /^log_queries[[:space:]]*=/ {
      sub(/=[[:space:]]*(true|false)/, "= " lq)
    }
    { print }
  ' "$SCRIPT_DIR/ferrous-dns-config.toml" > "$out"

  # Fail loudly rather than silently benchmarking the wrong configuration.
  local got_blk got_lq
  got_blk=$(awk '/^\[/{s=$0} s=="[blocking]" && /^enabled/{print $3}' "$out")
  got_lq=$(awk '/^\[/{s=$0} s=="[database]" && /^log_queries/{print $3}' "$out")
  if [[ "$got_blk" != "$blocking" || "$got_lq" != "$querylog" ]]; then
    err "config render failed: blocking=$got_blk (want $blocking), log_queries=$got_lq (want $querylog)"
    exit 1
  fi
}

prepare_scenario() {
  local scenario="$1"
  local blocking querylog
  blocking=$(scenario_blocking "$scenario")
  querylog=$(scenario_querylog "$scenario")

  mkdir -p "$RUN_DIR" "$RAW_DIR" "$RESULTS_DIR"

  render_ferrous_config "$blocking" "$querylog" "$RUN_DIR/ferrous-${scenario}.toml"
  export BENCH_FERROUS_CONFIG="./.run/ferrous-${scenario}.toml"

  if [[ "$blocking" == "true" ]]; then
    export BENCH_BLOCKY_CONFIG="./blocky-config-blocking.yml"
    ADGUARD_TEMPLATE="$SCRIPT_DIR/adguard-templates/AdGuardHome-blocking.yaml"
  else
    export BENCH_BLOCKY_CONFIG="./blocky-config.yml"
    ADGUARD_TEMPLATE="$SCRIPT_DIR/adguard-templates/AdGuardHome-plain.yaml"
  fi

  if [[ "$USE_DOCKER" == "true" && "$blocking" == "true" ]]; then
    log "Starting blocklist HTTP server..."
    start_service blocklist-server
    wait_for_http "$BLOCKLIST_URL" 30 || {
      err "blocklist-server did not come up — scenario $scenario cannot run"
      return 1
    }
  fi
}

# ── stub upstream ────────────────────────────────────────────────────────────
# Brought up once and left running for the whole suite. Every server forwards
# here, so a cache miss costs a loopback round-trip instead of an internet
# round-trip. Without it, a working set larger than the caches measures the link
# rather than the server: the first version of this harness recorded ferrous-dns
# at 5,498 QPS with 120 ms average latency for exactly that reason.
start_stub_upstream() {
  [[ "$USE_DOCKER" == "true" ]] || return 0
  log "Starting stub upstream on 127.0.0.1:5300..."
  start_service stub-upstream
  if ! wait_for_dns 127.0.0.1 5300 "stub upstream" 30; then
    err "stub upstream did not come up — every measurement would be a test of"
    err "the internet link instead of the server under test. Refusing to continue."
    exit 1
  fi
}

# ── AdGuard config staging ───────────────────────────────────────────────────
# AdGuard rewrites its config in place and re-chowns it to root:0600, so the
# tracked templates are copied into a scratch directory instead of being mounted.
stage_adguard() {
  sudo_rm "$RUN_DIR/adguard-conf" "$RUN_DIR/adguard-work"
  mkdir -p "$RUN_DIR/adguard-conf" "$RUN_DIR/adguard-work"
  cp "$ADGUARD_TEMPLATE" "$RUN_DIR/adguard-conf/AdGuardHome.yaml"
  chmod 666 "$RUN_DIR/adguard-conf/AdGuardHome.yaml"
  chmod 777 "$RUN_DIR/adguard-conf" "$RUN_DIR/adguard-work"
}

# Directories written by root-owned containers cannot be removed as the host
# user. Fall back to a throwaway container that owns the same mount.
sudo_rm() {
  local target
  for target in "$@"; do
    [[ -e "$target" ]] || continue
    rm -rf "$target" 2>/dev/null && continue
    docker run --rm -v "$(dirname "$target"):/wipe" alpine:3.22 \
      rm -rf "/wipe/$(basename "$target")" >/dev/null 2>&1 || true
  done
}

# ── run dnsperf, capture raw NDJSON ──────────────────────────────────────────
# dnsperf -j emits one JSON object per line: a "start" record, one "rate" record
# per -S interval, a "stop" record and a final "statistics" record. Parsing that
# is far more robust than scraping the human-readable text, and the per-interval
# rates give enough samples for meaningful p5/p95 within a run.
#
# The -O suppress list matters: dnsperf writes "[Timeout] Query timed out" and
# friends to STDOUT, interleaved with the JSON, which turns the output into
# something no JSON parser will accept. Those events are not lost — they are
# counted in the statistics record as `lost`, which the report publishes.
run_dnsperf() {
  local host="$1" port="$2" out="$3"

  "${TASKSET[@]}" dnsperf \
    -s "$host" \
    -p "$port" \
    -d "$QUERIES_FILE" \
    -l "$DURATION" \
    -c "$CLIENTS" \
    -T "$CLIENTS" \
    -q 1000 \
    -S 1 \
    -j \
    -O suppress=timeouts,congestion,sendfailed,sockready,unexpected \
    > "$out" 2>"$out.stderr" || true

  if ! grep -q '"statistics"' "$out"; then
    warn "dnsperf produced no statistics record (see $out.stderr)"
    return 1
  fi
  return 0
}

warm_up() {
  local host="$1" port="$2" name="$3"
  # The warm-up has to actually populate the cache. With a working set this size
  # a 5-second warm-up leaves most of the stream missing, and the measurement
  # becomes a test of the upstream path rather than of the server.
  log "Warming up ${name} (${WARMUP}s)..."
  "${TASKSET[@]}" dnsperf -s "$host" -p "$port" -d "$QUERIES_FILE" \
    -l "$WARMUP" -c "$CLIENTS" -q 500 \
    -O suppress=timeouts,congestion,sendfailed,sockready,unexpected &>/dev/null || true
}

# ── readiness probes ─────────────────────────────────────────────────────────
wait_for_dns() {
  local host="$1" port="$2" name="$3" max_wait="${4:-30}"
  log "Waiting for ${name} on ${host}:${port} (up to ${max_wait}s)..."

  local count=0
  while [[ $count -lt $max_wait ]]; do
    if dig +short +time=1 +tries=1 -p "$port" "@$host" google.com A &>/dev/null; then
      ok "${name} is ready"
      return 0
    fi
    sleep 1
    count=$((count + 1))
  done
  warn "${name} did not respond within ${max_wait}s"
  return 1
}

wait_for_http() {
  local url="$1" max_wait="${2:-30}" count=0
  while [[ $count -lt $max_wait ]]; do
    if curl -fsS -o /dev/null --max-time 2 "$url" 2>/dev/null; then
      return 0
    fi
    sleep 1
    count=$((count + 1))
  done
  return 1
}

# ── canary probe ─────────────────────────────────────────────────────────────
# Answers the only question that makes scenario B meaningful: is the blocking
# engine actually rejecting these names, and which rule syntaxes reach it?
#
# The control name shares the canary zone but has no rule, so its answer is the
# baseline for "not blocked". Comparing against it works regardless of whether a
# server answers blocks with 0.0.0.0, NXDOMAIN or REFUSED.
CANARY_CONTROL="not-blocked.canary.example"
# Readiness gate, written into the hosts blocklist by generate-blocklist.py and
# deliberately not one of the reported probes — see the comment there.
CANARY_GATE="blocked-gate.canary.example"
CANARY_PROBES=(
  "blocked-exact.canary.example|exact hosts rule"
  "sub.blocked-wildcard.canary.example|wildcard suffix rule"
  "blocked-adblock.canary.example|adblock rule, apex"
  "sub.blocked-adblock.canary.example|adblock rule, subdomain"
  "x-blocked-ac-canary-y.canary.example|Aho-Corasick substring rule"
)

probe_answer() {
  local host="$1" port="$2" name="$3"
  local status answer
  # `set -o pipefail` is on, and grep exits 1 when a probe gets no answer at
  # all, so every one of these needs an explicit fallback or a failed probe
  # takes the whole suite down with it.
  status=$(dig +noall +comments +time=2 +tries=1 -p "$port" "@$host" "$name" A 2>/dev/null \
             | grep -oP 'status: \K[A-Z]+' | head -1 || true)
  answer=$(dig +short +time=2 +tries=1 -p "$port" "@$host" "$name" A 2>/dev/null \
             | tr '\n' ',' | sed 's/,$//' || true)
  echo "${status:-TIMEOUT}|${answer}"
}

# Probe every canary once and emit the JSON record. Returns the number of
# syntaxes that reached the matcher.
canary_snapshot() {
  local host="$1" port="$2" out="$3"
  local control
  control=$(probe_answer "$host" "$port" "$CANARY_CONTROL")

  local entries=()
  local probe name desc result blocked
  for probe in "${CANARY_PROBES[@]}"; do
    name="${probe%%|*}"
    desc="${probe##*|}"
    result=$(probe_answer "$host" "$port" "$name")
    if [[ "$result" == "$control" ]]; then blocked=false; else blocked=true; fi
    entries+=("$(printf '{"probe":"%s","catches":"%s","response":"%s","blocked":%s}' \
      "$name" "$desc" "$result" "$blocked")")
  done

  printf '{"control":{"probe":"%s","response":"%s"},"probes":[%s]}' \
    "$CANARY_CONTROL" "$control" \
    "$(IFS=,; echo "${entries[*]}")" > "$out"

  grep -c '"blocked":true' "$out" || true
}

# Wait for the blocklist to be live, then probe the reported canaries exactly
# once.
#
# Answering DNS is not the same as having a blocklist: AdGuard Home downloads and
# parses its filter asynchronously after it starts serving, and ferrous-dns
# compiles a million rules at boot. Polling has to happen — but it must not
# happen on the names being reported. ferrous-dns memoises every block decision
# for 60 seconds (TTL_SECS in decision_cache.rs), so a probe issued one second
# before the index compiles pins "allowed" for the next minute and the report
# would understate the engine. Hence a throwaway gate name.
run_canary_probes() {
  local host="$1" port="$2" out="$3" max_wait="${4:-240}"
  local count=0 gate control live=false

  log "Waiting for the blocklist to go live (up to ${max_wait}s)..."
  while [[ $count -lt $max_wait ]]; do
    control=$(probe_answer "$host" "$port" "$CANARY_CONTROL")
    gate=$(probe_answer "$host" "$port" "$CANARY_GATE")
    # A timed-out control differs from everything, which would read as "blocked"
    # and declare the list live while the index is still empty. Only trust the
    # comparison once the control itself answers.
    if [[ "$control" != TIMEOUT* && "$gate" != TIMEOUT* && "$gate" != "$control" ]]; then
      ok "blocklist is live after ${count}s"
      live=true
      break
    fi
    sleep 3
    count=$((count + 3))
  done

  # One more source may still be compiling, and — more importantly — any verdict
  # reached before the index was complete is pinned in ferrous-dns's block
  # decision cache for TTL_SECS (60s, decision_cache.rs). Waiting out a full TTL
  # is the only way to be sure the snapshot reflects the engine and not a stale
  # entry from the readiness poll.
  if [[ "$live" == "true" ]]; then
    log "Letting the block decision cache expire (65s) before probing..."
    sleep 65
  fi

  local n
  n=$(canary_snapshot "$host" "$port" "$out")
  if [[ "$n" -le 0 ]]; then
    warn "No canary was blocked — treat this server's scenario B/C numbers as"
    warn "blocking-disabled rather than as a blocking measurement."
  fi
  log "Canary: ${n}/${#CANARY_PROBES[@]} rule syntaxes reach the engine"
}

# ── Docker service management ────────────────────────────────────────────────
# --wait blocks until the healthcheck passes. --wait-timeout bounds that: a
# container that serves DNS correctly but reports unhealthy (Blocky's healthcheck
# defaults to port 53, for one) should cost seconds, not stall the suite. The
# real readiness gate is wait_for_dns, which queries the server directly.
start_service() {
  docker compose -f "$DOCKER_COMPOSE" up -d --wait --wait-timeout 60 "$1" >/dev/null 2>&1 || \
    docker compose -f "$DOCKER_COMPOSE" up -d "$1" >/dev/null 2>&1
}

stop_service() {
  docker compose -f "$DOCKER_COMPOSE" stop "$1" >/dev/null 2>&1 || true
}

restart_service() {
  docker compose -f "$DOCKER_COMPOSE" restart "$1" >/dev/null 2>&1 || true
}

stop_everything() {
  if [[ "$USE_DOCKER" == "true" ]]; then
    log "Tearing down containers..."
    docker compose -f "$DOCKER_COMPOSE" down >/dev/null 2>&1 || true
  fi
}

# ── ferrous-dns blocklist seeding ────────────────────────────────────────────
# The blocklist tables have no CLI import path, and the manual `blocklist` table
# only feeds the exact matcher (compiler.rs passes it straight into the hash map
# without going through parse_list_line). Registering blocklist_sources rows and
# letting the compiler fetch the text over HTTP is the only route that populates
# the suffix trie and the Aho-Corasick automaton as well.
#
# Creating a source does not recompile the index, so the container is restarted
# and the compile happens at boot.
seed_ferrous_blocklist() {
  local host="$1" port="$2"

  log "Registering blocklist sources with ferrous-dns..."
  local code
  for entry in "bench-hosts|$BLOCKLIST_URL" "bench-advanced|$BLOCKLIST_ADVANCED_URL"; do
    code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$FERROUS_API/blocklist-sources" \
      -H 'Content-Type: application/json' \
      -d "{\"name\":\"${entry%%|*}\",\"url\":\"${entry##*|}\",\"group_ids\":[1],\"enabled\":true}" \
      2>/dev/null || echo 000)
    case "$code" in
      201|409) ;;
      401|403) err "ferrous-dns API requires auth — set [auth] enabled = false in the bench config"
               return 1 ;;
      *) err "failed to register ${entry%%|*} (HTTP $code)"; return 1 ;;
    esac
  done

  log "Restarting ferrous-dns so it compiles the blocklist at boot..."
  restart_service ferrous-dns
  wait_for_dns "$host" "$port" "🦀 ferrous-dns" 180 || return 1
  return 0
}

# ── benchmark one server for one scenario ────────────────────────────────────
bench_server() {
  local scenario="$1" key="$2"
  local meta svc disp port
  meta=$(server_meta "$key")
  svc="${meta%%|*}"; meta="${meta#*|}"
  disp="${meta%%|*}"; port="${meta##*|}"

  local host="127.0.0.1"
  [[ "$key" == "ferrous" ]] && host="${FERROUS_ADDR%%:*}"

  local blocking
  blocking=$(scenario_blocking "$scenario")
  local prefix="$RAW_DIR/${scenario}.${key}"

  echo "{\"scenario\":\"$scenario\",\"key\":\"$key\",\"display\":\"$disp\",\"status\":\"pending\"}" \
    > "$prefix.meta.json"

  if [[ "$USE_DOCKER" == "true" ]]; then
    [[ "$key" == "adguard" ]] && stage_adguard
    if [[ "$key" == "ferrous" && "$blocking" == "true" ]]; then
      # Fresh database per blocking scenario: a stale one would keep the sources
      # from the previous scenario and double the rule count.
      stop_service ferrous-dns
      sudo_rm "$RUN_DIR/db"
      mkdir -p "$RUN_DIR/db"; chmod 777 "$RUN_DIR/db"
    fi

    log "Starting ${disp} (scenario ${scenario})..."
    if ! start_service "$svc"; then
      warn "Failed to start ${svc} — skipping"
      echo "{\"scenario\":\"$scenario\",\"key\":\"$key\",\"display\":\"$disp\",\"status\":\"start-failed\"}" \
        > "$prefix.meta.json"
      return
    fi
  fi

  # AdGuard and Blocky download and compile a 30 MB list before answering.
  local ready_wait=45
  [[ "$blocking" == "true" ]] && ready_wait=240

  if ! wait_for_dns "$host" "$port" "$disp" "$ready_wait"; then
    echo "{\"scenario\":\"$scenario\",\"key\":\"$key\",\"display\":\"$disp\",\"status\":\"unreachable\"}" \
      > "$prefix.meta.json"
    [[ "$USE_DOCKER" == "true" ]] && stop_service "$svc"
    return
  fi

  if [[ "$key" == "ferrous" && "$blocking" == "true" && "$USE_DOCKER" == "true" ]]; then
    seed_ferrous_blocklist "$host" "$port" || {
      echo "{\"scenario\":\"$scenario\",\"key\":\"$key\",\"display\":\"$disp\",\"status\":\"seed-failed\"}" \
        > "$prefix.meta.json"
      stop_service "$svc"
      return
    }
  fi

  if [[ "$blocking" == "true" ]]; then
    run_canary_probes "$host" "$port" "$prefix.canary.json" 240
  fi

  warm_up "$host" "$port" "$disp"

  local completed=0 i
  for (( i = 1; i <= RUNS; i++ )); do
    log "${disp} — run ${i}/${RUNS} (${DURATION}s, ${CLIENTS} clients)"
    if run_dnsperf "$host" "$port" "$prefix.run${i}.json"; then
      completed=$((completed + 1))
      local qps
      # -R with fromjson? tolerates any stray non-JSON line dnsperf may still
      # emit; the trailing `|| true` keeps a progress message from aborting a
      # measurement run under `set -e`.
      qps=$(jq -rR 'fromjson? | select(.statistics) | .statistics.qps | round' \
              "$prefix.run${i}.json" 2>/dev/null | head -1) || true
      ok "${disp} run ${i}: ${qps:-?} QPS"
    fi
  done

  echo "{\"scenario\":\"$scenario\",\"key\":\"$key\",\"display\":\"$disp\",\"status\":\"ok\",\"runs\":$completed}" \
    > "$prefix.meta.json"

  # Scenario C only: the query-log channel drops silently when full (try_send
  # returns Ok), so the warning count is the only evidence rows were lost.
  if [[ "$key" == "ferrous" && "$(scenario_querylog "$scenario")" == "true" && "$USE_DOCKER" == "true" ]]; then
    local drops
    drops=$(docker compose -f "$DOCKER_COMPOSE" logs ferrous-dns 2>/dev/null \
              | grep -c "Query log channel full" || true)
    echo "{\"query_log_channel_full_warnings\":${drops:-0}}" > "$prefix.querylog.json"
    [[ "${drops:-0}" -gt 0 ]] && warn "ferrous-dns dropped query-log entries (${drops} channel-full warnings)"
  fi

  [[ "$USE_DOCKER" == "true" ]] && { log "Stopping ${disp}..."; stop_service "$svc"; }
  return 0
}

# ── provenance ───────────────────────────────────────────────────────────────
# A benchmark number without the build that produced it is not reproducible.
# Recorded verbatim into the report rather than described in prose.
write_provenance() {
  local binary="$REPO_DIR/target/release/ferrous-dns"
  local version="unknown" sha dirty="clean"
  [[ -x "$binary" ]] && version=$("$binary" --version 2>/dev/null | head -1)
  sha=$(git -C "$REPO_DIR" rev-parse HEAD 2>/dev/null || echo unknown)
  [[ -n "$(git -C "$REPO_DIR" status --porcelain 2>/dev/null)" ]] && dirty="dirty"

  python3 - "$RUN_DIR/provenance.json" <<PYEOF
import json, os, platform, subprocess, sys

def sh(*cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True).stdout.strip()
    except Exception:
        return ""

data = {
    "generated_utc": sh("date", "-u", "+%Y-%m-%d %H:%M:%S UTC"),
    "ferrous_version": """$version""".strip(),
    "git_sha": """$sha""".strip(),
    "git_worktree": """$dirty""".strip(),
    "rustflags": os.environ.get(
        "RUSTFLAGS",
        "-C target-cpu=native (the documented build line; RUSTFLAGS was not set "
        "in the shell that ran the benchmark, so this is the intended value, not "
        "an observed one)",
    ),
    "binary_origin": "locally built target/release/ferrous-dns, copied into the bench image",
    "kernel": platform.release(),
    "cpu_model": next((l.split(":", 1)[1].strip()
                       for l in open("/proc/cpuinfo") if l.startswith("model name")), "unknown"),
    "cpu_threads": os.cpu_count(),
    "server_cpuset": os.environ.get("BENCH_SERVER_CPUS", "unpinned"),
    "loadgen_cpuset": """$LOADGEN_CPUS""".strip() or "unpinned",
    "profile": """$PROFILE""".strip(),
    "duration_secs": $DURATION,
    "warmup_secs": $WARMUP,
    "runs": $RUNS,
    "clients": $CLIENTS,
}
with open(sys.argv[1], "w") as f:
    json.dump(data, f, indent=2)
PYEOF
}

# ── main ─────────────────────────────────────────────────────────────────────
main() {
  echo ""
  echo -e "${BOLD}╔══════════════════════════════════════════════════════╗${RESET}"
  echo -e "${BOLD}║       ferrous-dns Performance Benchmark Suite        ║${RESET}"
  echo -e "${BOLD}╚══════════════════════════════════════════════════════╝${RESET}"
  echo ""

  check_prereqs
  setup_cpu_isolation
  ensure_datasets

  mkdir -p "$RUN_DIR" "$RAW_DIR" "$RESULTS_DIR" "$RUN_DIR/db"
  chmod 777 "$RUN_DIR/db" 2>/dev/null || true

  # Only clear the scenarios about to be re-measured. Running `--scenario B` on
  # its own should not silently drop the scenario A results the report needs to
  # compute the A → B → C deltas.
  local s
  for s in "${SCENARIOS[@]}"; do
    rm -f "$RAW_DIR/$s."*.json "$RAW_DIR/$s."*.stderr 2>/dev/null || true
  done

  [[ "$USE_DOCKER" == "true" ]] && trap stop_everything EXIT

  start_stub_upstream

  local scenario key
  for scenario in "${SCENARIOS[@]}"; do
    echo ""
    log "${BOLD}Scenario ${scenario}${RESET} — blocking=$(scenario_blocking "$scenario"), query_log=$(scenario_querylog "$scenario"), ${RUNS} runs x ${DURATION}s"
    prepare_scenario "$scenario" || continue
    for key in $(scenario_servers "$scenario"); do
      bench_server "$scenario" "$key"
    done
  done

  write_provenance

  log "Aggregating results..."
  python3 "$SCRIPT_DIR/aggregate-results.py" \
    --raw-dir "$RAW_DIR" \
    --results-dir "$RESULTS_DIR" \
    --provenance "$RUN_DIR/provenance.json" \
    --queries-manifest "$QUERIES_FILE.manifest.json" \
    --blocklist-manifest "$DATA_DIR/blocklist.manifest.json" \
    --output "$OUTPUT_FILE"

  ok "Report written to ${OUTPUT_FILE}"
}

main "$@"
