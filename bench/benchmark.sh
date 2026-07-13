#!/usr/bin/env bash
# =============================================================================
# ferrous-dns — Performance Benchmark vs. Competitors
# =============================================================================
# Measures QPS, average/worst-case latency and loss against:
#   - ferrous-dns (this project)
#   - Pi-hole
#   - AdGuard Home
#   - Unbound
#   - Blocky
#   - PowerDNS Recursor
#
# Prerequisites:
#   - dnsperf  (DNS-OARC):  apt install dnsperf  |  brew install dnsperf
#   - docker + docker compose
#   - taskset (util-linux) — optional; enables CPU isolation on Linux so the
#     load generator and server-under-test don't contend for cores
#   - A running ferrous-dns instance (or pass FERROUS_DNS_ADDR)
#
# Each server is started, warmed, measured, and stopped one at a time; dnsperf
# is pinned to a separate core set from the server to keep results reproducible.
#
# Usage:
#   ./bench/benchmark.sh [options]
#
# Options:
#   --duration   <s>     Benchmark duration per server in seconds (default: 60)
#   --clients    <n>     Concurrent dnsperf clients (default: 10)
#   --ferrous    <addr>  ferrous-dns address (default: 127.0.0.1:5353)
#   --no-docker          Skip starting competitor containers
#   --output     <file>  Save Markdown report to file
#   --help               Show this help
# =============================================================================

set -euo pipefail

# ── defaults ────────────────────────────────────────────────────────────────
DURATION=${DURATION:-60}
CLIENTS=${CLIENTS:-10}
FERROUS_ADDR=${FERROUS_DNS_ADDR:-"127.0.0.1:5353"}
QUERIES_FILE="$(dirname "$0")/data/queries.txt"
DOCKER_COMPOSE="$(dirname "$0")/docker-compose.yml"
USE_DOCKER=true
OUTPUT_FILE=""
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ── CPU isolation state (populated by setup_cpu_isolation) ───────────────────
# dnsperf (the load generator) and the server-under-test must not share cores,
# otherwise they fight for CPU and the kernel drops UDP on loopback — noise that
# dnsperf mis-reports as "lost". TASKSET pins dnsperf to a dedicated core set.
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
    --duration)  DURATION="$2"; shift 2 ;;
    --clients)   CLIENTS="$2"; shift 2 ;;
    --ferrous)   FERROUS_ADDR="$2"; shift 2 ;;
    --no-docker) USE_DOCKER=false; shift ;;
    --output)    OUTPUT_FILE="$2"; shift 2 ;;
    --help)
      sed -n '/^# Usage/,/^# =====/p' "$0" | head -n -1
      exit 0 ;;
    *) err "Unknown option: $1"; exit 1 ;;
  esac
done

# ── prerequisite checks ──────────────────────────────────────────────────────
check_prereqs() {
  local missing=false

  if ! command -v dnsperf &>/dev/null; then
    err "dnsperf not found. Install it:"
    err "  Debian/Ubuntu: apt install dnsperf"
    err "  Arch:          pacman -S dnsperf"
    err "  macOS:         brew install dnsperf"
    missing=true
  fi

  if [[ "$USE_DOCKER" == "true" ]] && ! command -v docker &>/dev/null; then
    warn "docker not found — skipping competitor containers (--no-docker implied)"
    USE_DOCKER=false
  fi

  if [[ ! -f "$QUERIES_FILE" ]]; then
    err "Query dataset not found: $QUERIES_FILE"
    missing=true
  fi

  if [[ "$missing" == "true" ]]; then exit 1; fi
}

# ── CPU isolation setup ──────────────────────────────────────────────────────
# Splits the host cores in half: the lower half runs the server-under-test
# (exported to docker-compose via BENCH_SERVER_CPUS / BENCH_SERVER_NCPU), the
# upper half runs dnsperf (via the TASKSET prefix). Requires Linux + taskset +
# at least 4 cores; otherwise pinning is skipped and defaults (0-15 / 16) apply.
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

  # Consumed by docker-compose.yml (cpuset / cpus) for every server container.
  export BENCH_SERVER_CPUS="$server_cpus"
  export BENCH_SERVER_NCPU="$half"

  log "CPU isolation: server on cores ${server_cpus}, dnsperf on cores ${LOADGEN_CPUS}"
}

# ── run dnsperf and parse output ─────────────────────────────────────────────
# Returns: "QPS AVG_ms MAX_ms COMPLETED% LOST%"
run_dnsperf() {
  local name="$1" host="$2" port="$3"

  log "Benchmarking ${BOLD}${name}${RESET} (${host}:${port}) — ${DURATION}s, ${CLIENTS} clients..."

  # Filter comment lines from queries file
  local tmp_queries
  tmp_queries=$(mktemp)
  grep -v '^[[:space:]]*;' "$QUERIES_FILE" | grep -v '^[[:space:]]*$' > "$tmp_queries"

  local output
  output=$("${TASKSET[@]}" dnsperf \
    -s "$host" \
    -p "$port" \
    -d "$tmp_queries" \
    -l "$DURATION" \
    -c "$CLIENTS" \
    -T "$CLIENTS" \
    -q 1000 \
    2>&1) || true

  rm -f "$tmp_queries"

  # Parse dnsperf output
  local qps avg_s max_s completed lost
  qps=$(echo "$output"       | grep -oP 'Queries per second:\s+\K[\d.]+' || echo "0")
  lost=$(echo "$output"      | grep -oP 'Queries lost:\s+\d+ \(\K[\d.]+' || echo "0")
  completed=$(echo "$output" | grep -oP 'Queries completed:\s+\d+ \(\K[\d.]+' || echo "0")

  # dnsperf reports "Average Latency (s): <avg> (min <min>, max <max>)" — take
  # avg and the real worst-case max (both in seconds), convert to ms.
  avg_s=$(echo "$output" | grep -oP 'Average Latency \(s\):\s+\K[\d.]+' || echo "0")
  max_s=$(echo "$output" | grep -oP 'Average Latency.*max \K[\d.]+' || echo "0")
  local avg_ms max_ms
  avg_ms=$(awk "BEGIN { printf \"%.2f\", $avg_s * 1000 }")
  max_ms=$(awk "BEGIN { printf \"%.2f\", $max_s * 1000 }")

  echo "$qps $avg_ms $max_ms $completed $lost"
}

# ── warm up a DNS server ─────────────────────────────────────────────────────
warm_up() {
  local host="$1" port="$2" name="$3"
  log "Warming up ${name}..."

  # Warm the full query set so the measurement runs against a warm cache for
  # every domain, not just the first 20.
  local tmp
  tmp=$(mktemp)
  grep -v '^[[:space:]]*;' "$QUERIES_FILE" | grep -v '^[[:space:]]*$' > "$tmp"

  "${TASKSET[@]}" dnsperf -s "$host" -p "$port" -d "$tmp" -l 5 -c 2 -q 100 &>/dev/null || true
  rm -f "$tmp"
}

# ── wait for a DNS port to be reachable ─────────────────────────────────────
wait_for_dns() {
  local host="$1" port="$2" name="$3" max_wait="${4:-30}"
  log "Waiting for ${name} on ${host}:${port}..."

  local count=0
  local _tmp_q
  _tmp_q=$(mktemp)
  echo "google.com A" > "$_tmp_q"
  while ! "${TASKSET[@]}" dnsperf -s "$host" -p "$port" -d "$_tmp_q" -l 1 -c 1 -q 5 &>/dev/null \
        && [[ $count -lt $max_wait ]]; do
    sleep 1
    ((count++))
  done
  rm -f "$_tmp_q"

  if [[ $count -ge $max_wait ]]; then
    warn "${name} did not respond within ${max_wait}s — skipping"
    return 1
  fi
  ok "${name} is ready"
  return 0
}

# ── Docker competitor management ─────────────────────────────────────────────
# Start a single service and wait for its healthcheck. Servers are started one
# at a time (and stopped after) so an idle competitor never steals CPU from the
# server being measured. Returns non-zero if the service failed to come up.
start_service() {
  local svc="$1"
  docker compose -f "$DOCKER_COMPOSE" up -d --wait "$svc" 2>/dev/null || \
    docker-compose -f "$DOCKER_COMPOSE" up -d "$svc" 2>/dev/null
}

stop_service() {
  local svc="$1"
  docker compose -f "$DOCKER_COMPOSE" stop "$svc" 2>/dev/null || \
    docker-compose -f "$DOCKER_COMPOSE" stop "$svc" 2>/dev/null || true
}

# Safety net on exit: tear everything down.
stop_competitors() {
  if [[ "$USE_DOCKER" == "true" ]]; then
    log "Stopping competitor containers..."
    docker compose -f "$DOCKER_COMPOSE" down 2>/dev/null || \
      docker-compose -f "$DOCKER_COMPOSE" down 2>/dev/null || true
  fi
}

# ── benchmark one server end-to-end ──────────────────────────────────────────
# Starts the container (when USE_DOCKER), waits for it, warms it, measures it,
# appends a result row, then stops the container. In --no-docker mode the server
# is assumed to be already running at host:port.
bench_server() {
  local disp="$1" svc="$2" host="$3" port="$4"

  if [[ "$USE_DOCKER" == "true" ]]; then
    log "Starting ${disp}..."
    if ! start_service "$svc"; then
      warn "Failed to start ${svc} — skipping"
      ROWS+=("$(format_row "$disp" "N/A" "N/A" "N/A" "N/A" "N/A")")
      return
    fi
    if ! wait_for_dns "$host" "$port" "$disp" 30; then
      ROWS+=("$(format_row "$disp" "N/A" "N/A" "N/A" "N/A" "N/A")")
      stop_service "$svc"
      return
    fi
  elif ! wait_for_dns "$host" "$port" "$disp" 5; then
    warn "${disp} not reachable at ${host}:${port} — start it first or use docker"
    ROWS+=("$(format_row "$disp" "N/A" "N/A" "N/A" "N/A" "N/A")")
    return
  fi

  warm_up "$host" "$port" "$disp"
  local qps avg max comp lost
  read -r qps avg max comp lost < <(run_dnsperf "$disp" "$host" "$port")
  ROWS+=("$(format_row "$disp" "$qps" "$avg" "$max" "$comp" "$lost")")
  ok "${disp}: ${qps} QPS, avg ${avg}ms, max ${max}ms"

  [[ "$USE_DOCKER" == "true" ]] && { log "Stopping ${disp}..."; stop_service "$svc"; }
}

# ── format table row ─────────────────────────────────────────────────────────
format_row() {
  local name="$1" qps="$2" avg="$3" max="$4" completed="$5" lost="$6"
  printf "| %-18s | %10s | %10s | %10s | %12s%% | %10s%% |\n" \
    "$name" "$qps" "${avg}ms" "${max}ms" "$completed" "$lost"
}

# ── print markdown table ─────────────────────────────────────────────────────
print_table() {
  local -n rows_ref=$1
  local header separator

  header="| Server             |    QPS     | Avg Lat    |  Max Lat   | Completed   | Lost       |"
  separator="|:-------------------|:----------:|:----------:|:----------:|:-----------:|:----------:|"

  echo ""
  echo "$header"
  echo "$separator"
  for row in "${rows_ref[@]}"; do
    echo "$row"
  done
  echo ""
}

# ── save Markdown report ─────────────────────────────────────────────────────
save_report() {
  local -n rows_ref=$1

  cat > "$OUTPUT_FILE" <<EOF
# ferrous-dns — Performance Benchmark Results

> Generated: $(date -u '+%Y-%m-%d %H:%M:%S UTC')
> Duration per server: ${DURATION}s | Clients: ${CLIENTS} | Queries: $(grep -vc '^[[:space:]]*[;#]' "$QUERIES_FILE" 2>/dev/null || echo "N/A")

## Results

| Server             |    QPS     | Avg Lat    |  Max Lat   | Completed   | Lost       |
|:-------------------|:----------:|:----------:|:----------:|:-----------:|:----------:|
EOF

  for row in "${rows_ref[@]}"; do
    echo "$row" >> "$OUTPUT_FILE"
  done

  cat >> "$OUTPUT_FILE" <<'EOF'

## Methodology

- **Tool**: [dnsperf](https://www.dns-oarc.net/tools/dnsperf) by DNS-OARC
- **Query dataset**: `bench/data/queries.txt` (mix of A, AAAA, MX, TXT, NS)
- **Workload**: All servers use the same query dataset in loop mode
- **CPU isolation**: The load generator (dnsperf) is pinned to a separate set of
  cores from the server under test so they don't contend for CPU (Linux + taskset,
  ≥4 cores). Server containers are pinned to the complementary cores.
- **One server at a time**: each server is started, measured, and stopped before
  the next — an idle competitor never steals CPU during a measurement.
- **Warm-up**: full query set warmed before each measurement (warm cache)
- **Max Lat**: real worst-case latency reported by dnsperf (not an estimate)

## How to reproduce

```bash
# Install dnsperf
apt install dnsperf   # Debian/Ubuntu
brew install dnsperf  # macOS

# Run benchmark
./scripts/benchmark-competitors.sh --duration 30 --clients 10

# With custom ferrous-dns address
FERROUS_DNS_ADDR=192.168.1.10:53 ./scripts/benchmark-competitors.sh
```
EOF

  ok "Report saved to ${OUTPUT_FILE}"
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

  # Tear everything down on exit (safety net; servers are also stopped
  # individually after each measurement).
  if [[ "$USE_DOCKER" == "true" ]]; then
    trap stop_competitors EXIT
  fi

  declare -a ROWS

  # ferrous-dns address is configurable (may be an external instance in
  # --no-docker mode); competitors always run on loopback via docker.
  local ferrous_host ferrous_port
  ferrous_host="${FERROUS_ADDR%%:*}"
  ferrous_port="${FERROUS_ADDR##*:}"

  bench_server "🦀 ferrous-dns"    "ferrous-dns" "$ferrous_host" "$ferrous_port"
  bench_server "🕳️  Pi-hole"       "pihole"      "127.0.0.1"     "$PIHOLE_PORT"
  bench_server "🛡️  AdGuard Home"  "adguard"     "127.0.0.1"     "$ADGUARD_PORT"
  bench_server "⚡ Unbound"        "unbound"     "127.0.0.1"     "$UNBOUND_PORT"
  bench_server "🔷 Blocky"         "blocky"      "127.0.0.1"     "$BLOCKY_PORT"
  bench_server "⚡ PowerDNS (C++)" "powerdns"    "127.0.0.1"     "$POWERDNS_PORT"

  # ── Results ───────────────────────────────────────────────────────────────
  echo ""
  echo -e "${BOLD}Results (${DURATION}s benchmark, ${CLIENTS} concurrent clients)${RESET}"
  print_table ROWS

  if [[ -n "$OUTPUT_FILE" ]]; then
    save_report ROWS
  fi
}

main "$@"
