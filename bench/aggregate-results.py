#!/usr/bin/env python3
"""
Aggregate raw dnsperf output into the published benchmark report.

benchmark.sh keeps every measurement as raw dnsperf NDJSON and does no arithmetic
of its own; all statistics are computed here. The previous harness formatted each
row into a markdown string the moment it was measured, which discarded the
numbers and made a median across runs impossible to compute after the fact.

Two kinds of spread are reported, because they answer different questions:

  * median and min-max ACROSS runs   -> run-to-run variance, the thing the
    published variance note is about. With 3-5 runs a percentile across runs
    would be noise dressed up as precision, so it is not reported.

  * p5/p50/p95 of the per-second samples WITHIN runs -> whether throughput is
    steady or spiky. dnsperf -S 1 emits one such sample per second, which gives
    27 samples in the quick profile and ~145 in the publish profile.
"""

import argparse
import glob
import json
import os
from statistics import median

SCENARIOS = {
    "A": ("Cache only", "cache on, blocking off, query log off",
          "The theoretical ceiling: pure forwarding out of a warm cache."),
    "B": ("Blocking", "cache on, blocking on (1M rules), query log off",
          "What the blocking engine costs on top of scenario A."),
    "C": ("Full stack", "cache on, blocking on (1M rules), query log on",
          "What a user actually runs."),
}

# Order rows deterministically instead of by filesystem order.
SERVER_ORDER = ["ferrous", "unbound", "powerdns", "blocky", "adguard", "pihole"]


def percentile(values, p):
    if not values:
        return None
    s = sorted(values)
    if len(s) == 1:
        return s[0]
    k = (len(s) - 1) * p / 100.0
    lo, hi = int(k), min(int(k) + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (k - lo)


def load_run(path):
    """Extract the statistics record and every per-second rate sample."""
    stats, rates = None, []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if "statistics" in obj:
                stats = obj["statistics"]
            elif "rate" in obj:
                rates.append(obj["rate"]["qps"])
    if stats is None:
        return None
    return {"stats": stats, "rates": rates}


def collect(raw_dir):
    """Build {scenario: {server_key: aggregate}} from the raw files."""
    out = {}
    for meta_path in sorted(glob.glob(os.path.join(raw_dir, "*.meta.json"))):
        with open(meta_path) as f:
            meta = json.load(f)
        scenario, key = meta["scenario"], meta["key"]
        prefix = os.path.join(raw_dir, f"{scenario}.{key}")

        runs = []
        for run_path in sorted(glob.glob(prefix + ".run*.json")):
            r = load_run(run_path)
            if r:
                runs.append(r)

        entry = {
            "display": meta["display"],
            "status": meta["status"],
            "runs": len(runs),
        }

        if runs:
            qps = [r["stats"]["qps"] for r in runs]
            avg_lat = [r["stats"]["latency"]["avg"] * 1000 for r in runs]
            max_lat = [r["stats"]["latency"]["max"] * 1000 for r in runs]
            sent = sum(r["stats"]["sent"] for r in runs)
            lost = sum(r["stats"]["lost"] for r in runs)
            samples = [s for r in runs for s in r["rates"]]

            entry.update({
                "qps_median": median(qps),
                "qps_min": min(qps),
                "qps_max": max(qps),
                "qps_per_run": qps,
                "avg_latency_ms": median(avg_lat),
                "max_latency_ms": max(max_lat),
                "loss_percent": 100.0 * lost / sent if sent else 0.0,
                "queries_sent": sent,
                "queries_lost": lost,
                "interval_samples": len(samples),
                "qps_p5": percentile(samples, 5),
                "qps_p50": percentile(samples, 50),
                "qps_p95": percentile(samples, 95),
            })

        canary_path = prefix + ".canary.json"
        if os.path.exists(canary_path):
            with open(canary_path) as f:
                entry["canary"] = json.load(f)

        ql_path = prefix + ".querylog.json"
        if os.path.exists(ql_path):
            with open(ql_path) as f:
                entry.update(json.load(f))

        out.setdefault(scenario, {})[key] = entry
    return out


def fmt_int(v):
    return f"{v:,.0f}" if v is not None else "—"


def fmt_ms(v):
    return f"{v:.2f}ms" if v is not None else "—"


def scenario_table(servers):
    lines = [
        "| Server | Median QPS | QPS spread across runs | QPS p5–p95 within runs | Median avg lat | Loss |",
        "|:-------|-----------:|:-----------------------|:-----------------------|:--------------:|-----:|",
    ]
    keys = [k for k in SERVER_ORDER if k in servers]
    keys.sort(key=lambda k: -(servers[k].get("qps_median") or 0))
    for key in keys:
        s = servers[key]
        name = s["display"]
        if key == "ferrous":
            name = f"**{name}**"
        if s.get("qps_median") is None:
            lines.append(f"| {name} | — | — | — | — | _{s['status']}_ |")
            continue
        lines.append(
            f"| {name} | {fmt_int(s['qps_median'])} "
            f"| {fmt_int(s['qps_min'])} – {fmt_int(s['qps_max'])} "
            f"| {fmt_int(s['qps_p5'])} – {fmt_int(s['qps_p95'])} "
            f"| {fmt_ms(s['avg_latency_ms'])} "
            f"| {s['loss_percent']:.2f}% |"
        )
    return "\n".join(lines)


def canary_table(canary):
    lines = [
        "| Rule syntax | Probe | Reaches the engine | Response |",
        "|:------------|:------|:------------------:|:---------|",
    ]
    for p in canary["probes"]:
        mark = "✅ yes" if p["blocked"] else "❌ **no**"
        lines.append(f"| {p['catches']} | `{p['probe']}` | {mark} | `{p['response']}` |")
    lines.append(f"| _(control, no rule)_ | `{canary['control']['probe']}` | — "
                 f"| `{canary['control']['response']}` |")
    return "\n".join(lines)


def render(results, prov, qman, bman):
    q = qman.get("realised", {})
    qp = qman.get("params", {})
    b = bman.get("realised", {})

    out = []
    w = out.append

    w("# ferrous-dns — Performance Benchmark Results")
    w("")
    w(f"> Generated: {prov.get('generated_utc', 'unknown')}")
    w(f"> Profile: `{prov.get('profile')}` — {prov.get('runs')} runs × "
      f"{prov.get('duration_secs')}s per server, {prov.get('clients')} dnsperf clients")
    w("")
    w("This report is generated end to end by `bench/benchmark.sh`. Every number "
      "below comes from raw dnsperf output kept in `bench/results/`; nothing is "
      "transcribed by hand.")
    w("")

    # ── scenarios ────────────────────────────────────────────────────────────
    w("## Scenarios")
    w("")
    w("| | Cache | Blocking | Query log | Servers | What it measures |")
    w("|:--|:--|:--|:--|:--|:--|")
    w("| **A** | on | off | off | all six | Theoretical ceiling |")
    w("| **B** | on | on (1M rules) | off | ferrous-dns, Blocky, AdGuard | Cost of the blocking engine |")
    w("| **C** | on | on (1M rules) | on | ferrous-dns, Blocky, AdGuard | What a user actually runs |")
    w("")
    w("Unbound and PowerDNS Recursor appear only in scenario A: they have no "
      "blocking engine, so running them in B and C would compare different "
      "things. Pi-hole appears only in scenario A because loading a million "
      "rules into it means driving a gravity import, which is slow and brittle "
      "enough that it would become the thing under test.")
    w("")

    for code in ("A", "B", "C"):
        if code not in results:
            continue
        title, config, blurb = SCENARIOS[code]
        w(f"### Scenario {code} — {title}")
        w("")
        w(f"*{config}*. {blurb}")
        w("")
        w(scenario_table(results[code]))
        w("")

        ferrous = results[code].get("ferrous", {})
        if "query_log_channel_full_warnings" in ferrous:
            n = ferrous["query_log_channel_full_warnings"]
            if n:
                w(f"> **Query log dropped entries during this scenario:** {n} "
                  "\"channel full\" warnings. The query-log producer uses a "
                  "non-blocking `try_send` on a bounded channel and returns `Ok` "
                  "when it overflows, so rows are lost silently under saturation. "
                  "The QPS figure above is therefore the cost of *logging what fit*, "
                  "not of logging everything.")
            else:
                w("> The query log kept up: no \"channel full\" warnings during "
                  "this scenario, so every query that was answered was also recorded.")
            w("")

    # ── A → B → C delta ──────────────────────────────────────────────────────
    deltas = []
    for code in ("A", "B", "C"):
        f = results.get(code, {}).get("ferrous", {})
        if f.get("qps_median"):
            deltas.append((code, f["qps_median"]))
    if len(deltas) > 1:
        base = deltas[0][1]
        w("### What each feature costs")
        w("")
        w("| Scenario | ferrous-dns median QPS | vs. scenario A |")
        w("|:--|--:|--:|")
        for code, v in deltas:
            rel = "—" if code == deltas[0][0] else f"{100.0 * (v - base) / base:+.1f}%"
            w(f"| {code} | {fmt_int(v)} | {rel} |")
        w("")

    # ── canary ───────────────────────────────────────────────────────────────
    canary = None
    for code in ("B", "C"):
        c = results.get(code, {}).get("ferrous", {}).get("canary")
        if c:
            canary = c
            break
    if canary:
        w("## What the blocking engine actually matches")
        w("")
        w("Scenario B is only meaningful if the rules it loads are reachable. "
          "Before each measurement the harness probes one name per rule syntax "
          "and compares the answer against a control name in the same zone that "
          "has no rule at all, so the result holds regardless of how a server "
          "signals a block.")
        w("")
        w(canary_table(canary))
        w("")
        unreached = [p for p in canary["probes"] if not p["blocked"]]
        if unreached:
            w("> **Not every rule syntax reaches the matcher.** "
              "`BlockIndex::is_blocked` consults the bloom filter before the "
              "suffix trie and the Aho-Corasick automaton, but the compiler only "
              "calls `bloom.set()` for exact entries — wildcard and pattern rules "
              "are added to their structures and then gated behind a filter that "
              "was never told about them. Adblock-syntax rules (`||domain^`) parse "
              "as exact entries, so they match the apex and not its subdomains.")
            w(">")
            w("> Scenario B is therefore an honest measurement of the **exact-match "
              "path at 1M rules**, which is what the overwhelming majority of real "
              "blocklist entries are, and not of the wildcard or substring matchers.")
            w("")

    # ── workload ─────────────────────────────────────────────────────────────
    w("## Workload")
    w("")
    w("The dataset is generated, not checked in — `bench/generate-queries.py` and "
      "`bench/generate-blocklist.py` are deterministic given `--seed`, so these "
      "files reproduce byte for byte.")
    w("")
    w("| | |")
    w("|---|---|")
    w(f"| Recurring working set | {fmt_int(q.get('unique_hot_domains'))} domains, "
      f"Zipf α = {qp.get('zipf_alpha')} |")
    w(f"| Cold-tail (churn) | {fmt_int(q.get('unique_cold_domains'))} single-occurrence domains "
      f"({qp.get('churn_percent')}% of the stream) |")
    w(f"| Reverse names | {fmt_int(q.get('unique_ptr_names'))} (public IPv4 space only) |")
    w(f"| **Unique names total** | **{fmt_int(q.get('unique_names_total'))}** |")
    w(f"| Query lines | {fmt_int(q.get('total_lines'))}, looped for the run duration |")
    w(f"| Record type mix | {', '.join(f'{k} {v}%' for k, v in sorted((q.get('type_mix_percent') or {}).items()))} |")
    w(f"| Block rate of the stream | {q.get('block_rate_percent')}% |")
    w(f"| Blocklist rules | {fmt_int(b.get('exact_rules'))} exact "
      f"+ {fmt_int(b.get('wildcard_rules'))} wildcard "
      f"+ {fmt_int(b.get('pattern_rules'))} pattern |")
    w("")
    w("The working set is deliberately larger than the 100k L1 block-decision "
      "cache. Below that threshold every decision is memoised after warm-up and "
      "the benchmark measures a hash lookup instead of the DNS pipeline — which "
      "is what the previous 187-domain dataset did.")
    w("")
    w("Two caveats worth stating plainly:")
    w("")
    w("- dnsperf loops the datafile, so the cold-tail pool is only genuinely cold "
      "within a single pass. Sustained pressure on the decision cache comes from "
      "the working set exceeding its capacity, not from churn alone.")
    w("- Servers that answer faster consume more of the stream in the same wall "
      "time and therefore touch more unique names. That works against the fastest "
      "server in the table, not for it.")
    w("")

    # ── provenance ───────────────────────────────────────────────────────────
    w("## Build provenance")
    w("")
    w("| | |")
    w("|---|---|")
    w(f"| ferrous-dns version | `{prov.get('ferrous_version')}` |")
    w(f"| Git commit | `{prov.get('git_sha')}` ({prov.get('git_worktree')} worktree) |")
    w(f"| Build flags | `RUSTFLAGS=\"{prov.get('rustflags')}\"` |")
    w(f"| Binary origin | {prov.get('binary_origin')} |")
    w("")
    w("> **This is not the binary you download.** These numbers come from a build "
      "with `-C target-cpu=native`, which lets the compiler use every instruction "
      "set extension the benchmark host has. The published Docker image is built "
      "generically so it runs on any x86-64 machine, and will measure lower on the "
      "same hardware. Reproducing the tables above requires the build line in "
      "*How to reproduce*, not the released image.")
    w("")

    # ── machine ──────────────────────────────────────────────────────────────
    w("## Test machine")
    w("")
    w("| | |")
    w("|---|---|")
    w(f"| CPU | {prov.get('cpu_model')} |")
    w(f"| Threads | {prov.get('cpu_threads')} |")
    w(f"| Kernel | {prov.get('kernel')} |")
    w(f"| Server cpuset | `{prov.get('server_cpuset')}` |")
    w(f"| Load generator cpuset | `{prov.get('loadgen_cpuset')}` |")
    w("")
    w("The harness splits the host cores in half: every server under test runs "
      "pinned to the lower half with an identical CPU quota, and dnsperf runs "
      "pinned to the upper half so the load generator never steals CPU from the "
      "server it is measuring. Servers are started, measured and stopped one at a "
      "time, so an idle competitor never contends for cores.")
    w("")
    w("One asymmetry to disclose: ferrous-dns pins its Tokio workers to individual "
      "cores within the cpuset, while the other servers let their runtimes schedule "
      "freely inside the same cpuset.")
    w("")

    # ── methodology ──────────────────────────────────────────────────────────
    w("## Methodology")
    w("")
    w("- **Tool**: [dnsperf](https://www.dns-oarc.net/tools/dnsperf) by DNS-OARC, "
      "JSON output (`-j`), per-second sampling (`-S 1`)")
    w(f"- **Runs**: {prov.get('runs')} per server per scenario. Tables report the "
      "**median** across runs plus the full min–max spread")
    w("- **Percentiles**: p5/p95 are computed over the per-second throughput "
      "samples *within* runs. Percentiles across a handful of runs would be noise "
      "presented as precision, so they are not reported")
    w("- **Loss**: reported for every server in every scenario. Throughput without "
      "a loss rate is half a metric")
    w(f"- **Warm-up**: {prov.get('warmup_secs')}s against the full dataset before "
      "the first measured run. A short warm-up leaves most of a working set this "
      "size missing, which turns the measurement into a test of the upstream path")
    w("- **In-flight cap**: `-q 1000` per client")
    w("- **Fairness**: every server forwards to the same local stub upstream, "
      "loads the identical hosts-format blocklist in scenarios B and C, has its "
      "cache sized to hold the working set, and runs with rate limiting off and "
      "thread counts matched to the cpuset")
    w("")
    w("**Scope.** This is a cache-hit forwarding benchmark, not a recursion "
      "benchmark. Every server runs with its cache enabled and its upstreams "
      "pointed at a local stub, so Unbound and PowerDNS Recursor operate in "
      "forward mode rather than recursing from the root — not the workload they "
      "are built around. The numbers describe how fast each server answers from "
      "its own cache, which is what a home or LAN resolver spends most of its time "
      "doing. They say nothing about recursive resolution performance.")
    w("")
    w("**Why a stub upstream.** A working set this size is larger than any of these "
      "caches, so there is a permanent stream of misses. Sending it to a public "
      "resolver measures the round-trip time to that resolver rather than the "
      "server under test — an earlier version of this harness did exactly that and "
      "recorded ferrous-dns at 5,498 q/s with 120 ms average latency. The stub "
      "answers any name at any depth instantly over loopback, identically for "
      "every server.")
    w("")

    # ── reproduce ────────────────────────────────────────────────────────────
    w("## How to reproduce")
    w("")
    w("```bash")
    w("# Install prerequisites")
    w("pacman -S dnsperf bind    # Arch    (dig comes from bind)")
    w("apt install dnsperf dnsutils   # Debian/Ubuntu")
    w("")
    w("# Build the release binary — the bench image copies it in")
    w('RUSTFLAGS="-C target-cpu=native" cargo build --release -p ferrous-dns')
    w("docker compose -f bench/docker-compose.yml build ferrous-dns")
    w("")
    w("# One scenario, quick profile (~5 minutes)")
    w("./bench/benchmark.sh --scenario A")
    w("")
    w("# All three scenarios at publication settings")
    w("./bench/benchmark.sh --scenario all --profile publish")
    w("")
    w("# Regenerate the workload from scratch")
    w("./bench/benchmark.sh --scenario all --profile publish --regen")
    w("```")
    w("")
    w("Raw per-run dnsperf output is written to `bench/results/`. See "
      "`bench/README.md` for what each knob does.")

    return "\n".join(out) + "\n"


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--raw-dir", required=True)
    p.add_argument("--results-dir", required=True)
    p.add_argument("--provenance", required=True)
    p.add_argument("--queries-manifest", required=True)
    p.add_argument("--blocklist-manifest", required=True)
    p.add_argument("--output", required=True)
    args = p.parse_args()

    def load(path):
        try:
            with open(path) as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError):
            return {}

    results = collect(args.raw_dir)
    if not results:
        raise SystemExit(f"no measurements found in {args.raw_dir}")

    prov = load(args.provenance)
    qman = load(args.queries_manifest)
    bman = load(args.blocklist_manifest)

    os.makedirs(args.results_dir, exist_ok=True)
    for scenario, servers in results.items():
        out = os.path.join(args.results_dir, f"scenario-{scenario}.json")
        with open(out, "w") as f:
            json.dump({"scenario": scenario, "provenance": prov,
                       "servers": servers}, f, indent=2)
            f.write("\n")

    with open(args.output, "w") as f:
        f.write(render(results, prov, qman, bman))


if __name__ == "__main__":
    main()
