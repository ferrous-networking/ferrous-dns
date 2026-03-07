#!/usr/bin/env bash
# =============================================================================
# Ferrous-DNS — Performance Benchmark vs. Competitors
# =============================================================================
# Measures QPS, P50/P99 latency and cache hit throughput against:
#   - Ferrous-DNS (this project)
#   - Pi-hole
#   - AdGuard Home
#   - Unbound
#   - Blocky
#
# Prerequisites:
#   - dnsperf  (DNS-OARC):  apt install dnsperf  |  brew install dnsperf
#   - docker + docker compose
#   - A running Ferrous-DNS instance (or pass FERROUS_DNS_ADDR)
#
# Usage:
#   ./bench/benchmark.sh [options]
#
# Options:
#   --duration   <s>     Benchmark duration per server in seconds (default: 60)
#   --clients    <n>     Concurrent dnsperf clients (default: 10)
#   --ferrous    <addr>  Ferrous-DNS address (default: 127.0.0.1:5353)
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

# ── ports for competitor containers ─────────────────────────────────────────
PIHOLE_PORT=5354
ADGUARD_PORT=5355
UNBOUND_PORT=5356
BLOCKY_PORT=5357

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

# ── run dnsperf and parse output ─────────────────────────────────────────────
# Returns: "QPS P50_ms P99_ms"
run_dnsperf() {
  local name="$1" host="$2" port="$3"

  log "Benchmarking ${BOLD}${name}${RESET} (${host}:${port}) — ${DURATION}s, ${CLIENTS} clients..."

  # Filter comment lines from queries file
  local tmp_queries
  tmp_queries=$(mktemp)
  grep -v '^[[:space:]]*;' "$QUERIES_FILE" | grep -v '^[[:space:]]*$' > "$tmp_queries"

  local output
  output=$(dnsperf \
    -s "$host" \
    -p "$port" \
    -d "$tmp_queries" \
    -l "$DURATION" \
    -c "$CLIENTS" \
    -T "$CLIENTS" \
    -q 10000 \
    2>&1) || true

  rm -f "$tmp_queries"

  # Parse dnsperf output
  local qps p50_ms p99_ms completed lost
  qps=$(echo "$output"      | grep -oP 'Queries per second:\s+\K[\d.]+' || echo "0")
  p50_ms=$(echo "$output"   | grep -oP 'Average Latency.*?:\s+\K[\d.]+' || echo "0")
  lost=$(echo "$output"     | grep -oP 'Queries lost:\s+\d+ \(\K[\d.]+' || echo "0")
  completed=$(echo "$output" | grep -oP 'Queries completed:\s+\d+ \(\K[\d.]+' || echo "0")

  # dnsperf reports latency in seconds — convert to ms using awk
  local stddev avg_s
  avg_s="$p50_ms"
  stddev=$(echo "$output" | grep -oP 'Latency StdDev.*?:\s+\K[\d.]+' || echo "0")
  p50_ms=$(awk "BEGIN { printf \"%.2f\", $avg_s * 1000 }")

  # Estimate P99 from StdDev (approximation: avg + 2.33*stddev for normal distribution)
  p99_ms=$(awk "BEGIN { printf \"%.2f\", ($avg_s + 2.33 * $stddev) * 1000 }")

  echo "$qps $p50_ms $p99_ms $completed $lost"
}

# ── warm up a DNS server ─────────────────────────────────────────────────────
warm_up() {
  local host="$1" port="$2" name="$3"
  log "Warming up ${name}..."

  local tmp
  tmp=$(mktemp)
  grep -v '^[[:space:]]*;' "$QUERIES_FILE" | grep -v '^[[:space:]]*$' | head -20 > "$tmp"

  dnsperf -s "$host" -p "$port" -d "$tmp" -l 5 -c 2 -q 100 &>/dev/null || true
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
  while ! dnsperf -s "$host" -p "$port" -d "$_tmp_q" -l 1 -c 1 -q 5 &>/dev/null \
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
start_competitors() {
  log "Starting competitor containers..."
  docker compose -f "$DOCKER_COMPOSE" up -d --wait 2>/dev/null || \
    docker-compose -f "$DOCKER_COMPOSE" up -d 2>/dev/null || {
      warn "Failed to start containers. Run manually or use --no-docker."
      USE_DOCKER=false
    }
}

stop_competitors() {
  if [[ "$USE_DOCKER" == "true" ]]; then
    log "Stopping competitor containers..."
    docker compose -f "$DOCKER_COMPOSE" down 2>/dev/null || \
      docker-compose -f "$DOCKER_COMPOSE" down 2>/dev/null || true
  fi
}

# ── format table row ─────────────────────────────────────────────────────────
format_row() {
  local name="$1" qps="$2" p50="$3" p99="$4" completed="$5" lost="$6"
  printf "| %-18s | %10s | %10s | %10s | %12s%% | %10s%% |\n" \
    "$name" "$qps" "${p50}ms" "${p99}ms" "$completed" "$lost"
}

# ── print markdown table ─────────────────────────────────────────────────────
print_table() {
  local -n rows_ref=$1
  local header separator

  header="| Server             |    QPS     | Avg Lat    |  P99 Lat   | Completed   | Lost       |"
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
# Ferrous-DNS — Performance Benchmark Results

> Generated: $(date -u '+%Y-%m-%d %H:%M:%S UTC')
> Duration per server: ${DURATION}s | Clients: ${CLIENTS} | Queries: $(grep -vc '^[[:space:]]*[;#]' "$QUERIES_FILE" 2>/dev/null || echo "N/A")

## Results

| Server             |    QPS     | Avg Lat    |  P99 Lat   | Completed   | Lost       |
|:-------------------|:----------:|:----------:|:----------:|:-----------:|:----------:|
EOF

  for row in "${rows_ref[@]}"; do
    echo "$row" >> "$OUTPUT_FILE"
  done

  cat >> "$OUTPUT_FILE" <<'EOF'

## Methodology

- **Tool**: [dnsperf](https://www.dns-oarc.net/tools/dnsperf) by DNS-OARC
- **Query dataset**: `scripts/bench-data/queries.txt` (mix of A, AAAA, MX, TXT, NS)
- **Workload**: All servers use the same query dataset in loop mode
- **Warm-up**: 5s warm-up before each measurement
- **P99**: Estimated from average + 2.33×σ (dnsperf provides average + stddev)

## How to reproduce

```bash
# Install dnsperf
apt install dnsperf   # Debian/Ubuntu
brew install dnsperf  # macOS

# Run benchmark
./scripts/benchmark-competitors.sh --duration 30 --clients 10

# With custom Ferrous-DNS address
FERROUS_DNS_ADDR=192.168.1.10:53 ./scripts/benchmark-competitors.sh
```
EOF

  ok "Report saved to ${OUTPUT_FILE}"
}

# ── main ─────────────────────────────────────────────────────────────────────
main() {
  echo ""
  echo -e "${BOLD}╔══════════════════════════════════════════════════════╗${RESET}"
  echo -e "${BOLD}║       Ferrous-DNS Performance Benchmark Suite        ║${RESET}"
  echo -e "${BOLD}╚══════════════════════════════════════════════════════╝${RESET}"
  echo ""

  check_prereqs

  # Start competitor containers
  if [[ "$USE_DOCKER" == "true" ]]; then
    start_competitors
    trap stop_competitors EXIT
  fi

  declare -a ROWS

  # ── Ferrous-DNS ──────────────────────────────────────────────────────────
  local ferrous_host ferrous_port
  ferrous_host="${FERROUS_ADDR%%:*}"
  ferrous_port="${FERROUS_ADDR##*:}"

  if nc -z -u "$ferrous_host" "$ferrous_port" 2>/dev/null || \
     dig +short +timeout=1 google.com @"$ferrous_host" -p "$ferrous_port" &>/dev/null; then
    warm_up "$ferrous_host" "$ferrous_port" "Ferrous-DNS"
    read -r qps p50 p99 comp lost < <(run_dnsperf "Ferrous-DNS" "$ferrous_host" "$ferrous_port")
    ROWS+=("$(format_row "🦀 Ferrous-DNS" "$qps" "$p50" "$p99" "$comp" "$lost")")
    ok "Ferrous-DNS: ${qps} QPS, avg ${p50}ms, p99 ${p99}ms"
  else
    warn "Ferrous-DNS not reachable at ${FERROUS_ADDR} — start it first or set FERROUS_DNS_ADDR"
    ROWS+=("$(format_row "🦀 Ferrous-DNS" "N/A" "N/A" "N/A" "N/A" "N/A")")
  fi

  # ── Pi-hole ──────────────────────────────────────────────────────────────
  if [[ "$USE_DOCKER" == "true" ]] || wait_for_dns "127.0.0.1" "$PIHOLE_PORT" "Pi-hole" 5; then
    warm_up "127.0.0.1" "$PIHOLE_PORT" "Pi-hole"
    read -r qps p50 p99 comp lost < <(run_dnsperf "Pi-hole" "127.0.0.1" "$PIHOLE_PORT")
    ROWS+=("$(format_row "🕳️  Pi-hole" "$qps" "$p50" "$p99" "$comp" "$lost")")
    ok "Pi-hole: ${qps} QPS, avg ${p50}ms, p99 ${p99}ms"
  else
    ROWS+=("$(format_row "🕳️  Pi-hole" "N/A" "N/A" "N/A" "N/A" "N/A")")
  fi

  # ── AdGuard Home ─────────────────────────────────────────────────────────
  if [[ "$USE_DOCKER" == "true" ]] || wait_for_dns "127.0.0.1" "$ADGUARD_PORT" "AdGuard Home" 5; then
    warm_up "127.0.0.1" "$ADGUARD_PORT" "AdGuard Home"
    read -r qps p50 p99 comp lost < <(run_dnsperf "AdGuard Home" "127.0.0.1" "$ADGUARD_PORT")
    ROWS+=("$(format_row "🛡️  AdGuard Home" "$qps" "$p50" "$p99" "$comp" "$lost")")
    ok "AdGuard Home: ${qps} QPS, avg ${p50}ms, p99 ${p99}ms"
  else
    ROWS+=("$(format_row "🛡️  AdGuard Home" "N/A" "N/A" "N/A" "N/A" "N/A")")
  fi

  # ── Unbound ──────────────────────────────────────────────────────────────
  if [[ "$USE_DOCKER" == "true" ]] || wait_for_dns "127.0.0.1" "$UNBOUND_PORT" "Unbound" 5; then
    warm_up "127.0.0.1" "$UNBOUND_PORT" "Unbound"
    read -r qps p50 p99 comp lost < <(run_dnsperf "Unbound" "127.0.0.1" "$UNBOUND_PORT")
    ROWS+=("$(format_row "⚡ Unbound" "$qps" "$p50" "$p99" "$comp" "$lost")")
    ok "Unbound: ${qps} QPS, avg ${p50}ms, p99 ${p99}ms"
  else
    ROWS+=("$(format_row "⚡ Unbound" "N/A" "N/A" "N/A" "N/A" "N/A")")
  fi

  # ── Blocky ───────────────────────────────────────────────────────────────
  if [[ "$USE_DOCKER" == "true" ]] || wait_for_dns "127.0.0.1" "$BLOCKY_PORT" "Blocky" 5; then
    warm_up "127.0.0.1" "$BLOCKY_PORT" "Blocky"
    read -r qps p50 p99 comp lost < <(run_dnsperf "Blocky" "127.0.0.1" "$BLOCKY_PORT")
    ROWS+=("$(format_row "🔷 Blocky" "$qps" "$p50" "$p99" "$comp" "$lost")")
    ok "Blocky: ${qps} QPS, avg ${p50}ms, p99 ${p99}ms"
  else
    ROWS+=("$(format_row "🔷 Blocky" "N/A" "N/A" "N/A" "N/A" "N/A")")
  fi

  # ── Results ───────────────────────────────────────────────────────────────
  echo ""
  echo -e "${BOLD}Results (${DURATION}s benchmark, ${CLIENTS} concurrent clients)${RESET}"
  print_table ROWS

  if [[ -n "$OUTPUT_FILE" ]]; then
    save_report ROWS
  fi
}

main "$@"
