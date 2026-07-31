#!/usr/bin/env python3
"""
Generate the blocklist fixtures used by benchmark scenarios B and C.

Two files are produced, deliberately kept apart:

  blocklist.txt           ~95% of the rules, hosts format ("0.0.0.0 <domain>").
                          Hosts format is the only syntax ferrous-dns, Blocky and
                          AdGuard Home all parse identically, so this is the file
                          every server under test loads. Fairness depends on all
                          three seeing exactly the same rules.

  blocklist-advanced.txt  the remaining ~5%: wildcard ("*.domain") and
                          Aho-Corasick pattern ("/substring/") rules, plus the
                          canaries. Loaded by ferrous-dns only, because mixing
                          these syntaxes into the hosts file breaks AdGuard's
                          format detection.

Every domain listed in blocked-domains.txt (written by generate-queries.py) is
guaranteed to appear in blocklist.txt, so the realised block rate of the query
stream is the one the manifest promises. The rest is filler that brings the
index up to a production-sized rule count.

CANARIES
--------
The canary rules exist so the harness can assert, on every run, what the block
engine actually does:

  blocked-exact.canary.example              hosts rule    -> expected BLOCKED
  sub.blocked-wildcard.canary.example       *.  rule      -> expected BLOCKED
  blocked-adblock.canary.example            ||..^ rule    -> expected BLOCKED
  sub.blocked-adblock.canary.example        ||..^ rule    -> expected BLOCKED
  x-blocked-ac-canary-y.canary.example      /../ rule     -> expected BLOCKED

At the time of writing, only the first and third are actually blocked. See
BlockIndex::is_blocked (crates/infrastructure/src/dns/block_filter/block_index.rs)
-- the bloom filter is consulted before the suffix trie and the Aho-Corasick
automaton, but compiler.rs only ever calls bloom.set() for Exact entries, so
wildcard and pattern rules are unreachable. The harness records the observed
result rather than asserting the expected one, so the report always states the
engine's real behaviour.
"""

import argparse
import json
import os
import random
import sys

CANARY_ZONE = "canary.example"

# Readiness gate. Deliberately NOT one of the reported canaries: the harness
# polls this name to find out when the index is live, and every poll made before
# the index compiled leaves an "allowed" verdict sitting in ferrous-dns's block
# decision cache for 60 seconds. Burning a throwaway name on the gate keeps the
# reported canaries unprobed until the engine is actually ready, so what the
# report publishes is the engine's behaviour and not a stale cache entry.
GATE_RULE = "0.0.0.0 blocked-gate.canary.example"
GATE_PROBE = "blocked-gate.canary.example"

# (rule line, probe name, which file, what the rule is meant to catch)
CANARIES = [
    ("0.0.0.0 blocked-exact.canary.example",
     "blocked-exact.canary.example", "hosts", "exact hosts rule"),
    ("*.blocked-wildcard.canary.example",
     "sub.blocked-wildcard.canary.example", "advanced", "wildcard suffix rule"),
    ("||blocked-adblock.canary.example^",
     "blocked-adblock.canary.example", "advanced", "adblock rule, apex"),
    ("||blocked-adblock.canary.example^",
     "sub.blocked-adblock.canary.example", "advanced", "adblock rule, subdomain"),
    ("/blocked-ac-canary/",
     "x-blocked-ac-canary-y.canary.example", "advanced", "Aho-Corasick substring rule"),
]

AD_WORDS = [
    "ads", "adserv", "adtrack", "banner", "beacon", "click", "cpm", "doubleclick",
    "metrics", "pixel", "promo", "stats", "telemetry", "track", "trk", "analytics",
    "affiliate", "retarget", "popunder", "adnxs", "taboola", "outbrain", "criteo",
]
NET_WORDS = [
    "media", "network", "serve", "delivery", "exchange", "platform", "engine",
    "hub", "cloud", "edge", "sync", "tag", "collect", "events", "logger",
]
TLDS = ["com", "net", "io", "co", "info", "biz", "xyz", "online", "site", "click"]


def synth_ad_domains(rng, count, existing):
    out = []
    while len(out) < count:
        a = rng.choice(AD_WORDS)
        b = rng.choice(NET_WORDS)
        n = rng.randrange(1, 1000000)
        d = f"{a}{n}.{b}.{rng.choice(TLDS)}"
        if d in existing:
            continue
        existing.add(d)
        out.append(d)
    return out


def main():
    p = argparse.ArgumentParser(
        description="Generate blocklist fixtures for benchmark scenarios B and C.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--rules", type=int, default=1000000,
                   help="total rule count across both files")
    p.add_argument("--advanced-share", type=float, default=5.0,
                   help="percent of rules that are wildcard/pattern (ferrous only)")
    p.add_argument("--blocked-domains", default="data/blocked-domains.txt",
                   help="written by generate-queries.py; every entry is included")
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--out-dir", default="data")
    args = p.parse_args()

    rng = random.Random(args.seed)
    out_dir = os.path.abspath(args.out_dir)
    os.makedirs(out_dir, exist_ok=True)

    if not os.path.exists(args.blocked_domains):
        sys.exit(f"[blocklist] missing {args.blocked_domains} — "
                 f"run generate-queries.py first")

    with open(args.blocked_domains) as f:
        from_queries = [ln.strip() for ln in f if ln.strip()]

    n_advanced = int(args.rules * args.advanced_share / 100.0)
    n_exact = args.rules - n_advanced

    if len(from_queries) > n_exact:
        sys.exit(f"[blocklist] --rules {args.rules} is too small: the query set "
                 f"alone needs {len(from_queries)} exact rules")

    print(f"[blocklist] {len(from_queries)} rules from the query set, "
          f"padding to {n_exact} exact + {n_advanced} advanced", file=sys.stderr)

    taken = set(from_queries)
    filler = synth_ad_domains(rng, n_exact - len(from_queries) - 1, taken)

    # ── hosts file: every server under test loads this one ───────────────────
    hosts_path = os.path.join(out_dir, "blocklist.txt")
    with open(hosts_path, "w") as f:
        f.write("# ferrous-dns benchmark blocklist (hosts format)\n")
        f.write(f"# generated by generate-blocklist.py --seed {args.seed}\n")
        f.write(GATE_RULE + "\n")
        for line, _, where, _ in CANARIES:
            if where == "hosts":
                f.write(line + "\n")
        buf = []
        for d in from_queries + filler:
            buf.append(f"0.0.0.0 {d}")
            if len(buf) >= 100000:
                f.write("\n".join(buf) + "\n")
                buf = []
        if buf:
            f.write("\n".join(buf) + "\n")

    # ── advanced file: ferrous-dns only ──────────────────────────────────────
    n_wildcard = int(n_advanced * 0.8)
    n_pattern = n_advanced - n_wildcard - 4  # 4 advanced canary lines

    wildcard_bases = synth_ad_domains(rng, max(n_wildcard, 0), taken)
    advanced_path = os.path.join(out_dir, "blocklist-advanced.txt")
    with open(advanced_path, "w") as f:
        f.write("# ferrous-dns benchmark blocklist (wildcard + pattern rules)\n")
        f.write("# Loaded by ferrous-dns only: this syntax is not portable to\n")
        f.write("# the hosts-format lists the other servers consume.\n")
        seen_rules = set()
        for line, _, where, _ in CANARIES:
            if where == "advanced" and line not in seen_rules:
                seen_rules.add(line)
                f.write(line + "\n")
        buf = [f"*.{d}" for d in wildcard_bases]
        for _ in range(max(n_pattern, 0)):
            buf.append(f"/{rng.choice(AD_WORDS)}{rng.randrange(1, 100000)}/")
        for i in range(0, len(buf), 100000):
            f.write("\n".join(buf[i:i + 100000]) + "\n")

    manifest = {
        "generator": "generate-blocklist.py",
        "params": {
            "rules": args.rules,
            "advanced_share_percent": args.advanced_share,
            "seed": args.seed,
        },
        "realised": {
            "exact_rules": n_exact,
            "exact_from_query_set": len(from_queries),
            "exact_filler": len(filler),
            "wildcard_rules": len(wildcard_bases),
            "pattern_rules": max(n_pattern, 0),
        },
        "canaries": [
            {"rule": line, "probe": probe, "file": where, "catches": what}
            for line, probe, where, what in CANARIES
        ],
        "readiness_gate": {"rule": GATE_RULE, "probe": GATE_PROBE},
        "outputs": {
            "hosts": hosts_path,
            "advanced": advanced_path,
        },
        "notes": [
            "blocklist.txt is hosts format because it is the only syntax "
            "ferrous-dns, Blocky and AdGuard Home all parse the same way. All "
            "three servers load exactly this file.",
            "blocklist-advanced.txt is loaded by ferrous-dns only and exists to "
            "size the wildcard/pattern side of the index and to carry the "
            "canaries.",
        ],
    }
    manifest_path = os.path.join(out_dir, "blocklist.manifest.json")
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)
        f.write("\n")

    print(f"[blocklist] {hosts_path} ({n_exact} rules)", file=sys.stderr)
    print(f"[blocklist] {advanced_path} ({n_advanced} rules)", file=sys.stderr)


if __name__ == "__main__":
    main()
