#!/usr/bin/env python3
"""
Generate a realistic dnsperf query dataset for the ferrous-dns benchmark.

The published benchmark used to loop a 187-domain file. That working set fits
entirely in every cache layer under test, so it measured a hash lookup rather
than the DNS pipeline: cache eviction never fires, and the block decision cache
(L0 256/thread + L1 100k, TTL 60s) memoises every decision after warm-up.

This generator emits a stream with the shape real network traffic has:

  * a recurring working set sampled from a Zipf distribution (a few domains are
    very hot, a long tail is nearly cold),
  * a churn fraction of single-occurrence "cold tail" domains that no cache can
    have seen before within a pass,
  * a realistic record-type mix rather than A-only,
  * a controllable share of the stream that lands on blocked domains.

Three files are written:

  <out>                   the dnsperf datafile ("<name> <TYPE>" per line)
  <out>.manifest.json     every parameter plus the realised statistics
  blocked-domains.txt     the domains this stream expects to be blocked,
                          consumed by generate-blocklist.py so the query set and
                          the blocklist cannot drift apart

Everything is derived from --seed, so two runs with the same flags produce
byte-identical files.
"""

import argparse
import json
import os
import random
import sys
from collections import Counter

# ── record type mix ──────────────────────────────────────────────────────────
# PTR is drawn from its own pool of reverse names, so it is kept apart from the
# types that apply to forward domains.
PTR_SHARE = 0.03
FORWARD_TYPE_WEIGHTS = [
    ("A", 0.70),
    ("AAAA", 0.15),
    ("MX", 0.05),
    ("TXT", 0.04),
    ("NS", 0.03),
]

# ── vocabulary used to synthesise plausible-looking names ────────────────────
HEAD_WORDS = [
    "cdn", "api", "static", "img", "media", "assets", "edge", "cache", "node",
    "app", "web", "mail", "auth", "login", "shop", "store", "pay", "account",
    "video", "stream", "live", "chat", "cloud", "data", "files", "download",
    "search", "maps", "news", "blog", "forum", "wiki", "docs", "help", "status",
]
BODY_WORDS = [
    "nova", "vertex", "orbit", "quantum", "lumen", "aster", "flux", "prism",
    "cobalt", "ember", "harbor", "summit", "canvas", "beacon", "cipher", "delta",
    "onyx", "pixel", "raven", "sable", "tundra", "vector", "zenith", "atlas",
    "bramble", "citrus", "dune", "echo", "fable", "grove", "haven", "ivory",
    "juniper", "kestrel", "lattice", "meridian", "nimbus", "opal", "pinnacle",
    "quarry", "ridge", "solace", "thicket", "umber", "verdant", "willow",
]
TLDS = [
    "com", "net", "org", "io", "co", "dev", "app", "cloud", "tech", "info",
    "com.br", "co.uk", "de", "fr", "nl", "jp", "in", "shop", "xyz", "online",
]
SUBDOMAIN_PREFIXES = ["www", "cdn", "api", "static", "img", "m", "eu", "us", "a1"]

# First octets that are safely public. RFC 1918 space and loopback are excluded
# because ferrous-dns refuses private PTR lookups by default
# (block_private_ptr = true in bench/ferrous-dns-config.toml), which would turn
# every PTR query into a block and quietly contaminate the no-blocking scenario.
PUBLIC_FIRST_OCTETS = [
    1, 4, 8, 9, 13, 20, 23, 34, 35, 40, 44, 45, 51, 52, 54, 63, 64, 65, 66, 72,
    74, 77, 78, 80, 81, 85, 88, 91, 93, 94, 95, 96, 98, 99, 101, 104, 108, 128,
    129, 130, 131, 132, 134, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145,
    146, 147, 148, 149, 151, 152, 153, 155, 156, 157, 158, 159, 160, 161, 162,
    163, 164, 165, 166, 167, 168, 169, 170, 171, 173, 174, 176, 177, 178, 179,
    180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 193, 194, 195,
    196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210,
    211, 212, 213, 216, 217,
]

# The head of the Zipf distribution is seeded with the real domains the previous
# dataset used, so the hot end of the stream still looks like actual traffic.
REAL_HEAD_DOMAINS = [
    "google.com", "youtube.com", "facebook.com", "twitter.com", "instagram.com",
    "linkedin.com", "reddit.com", "wikipedia.org", "amazon.com", "apple.com",
    "microsoft.com", "github.com", "stackoverflow.com", "cloudflare.com",
    "netflix.com", "twitch.tv", "discord.com", "whatsapp.com", "tiktok.com",
    "zoom.us", "slack.com", "dropbox.com", "spotify.com", "paypal.com",
    "ebay.com", "office.com", "live.com", "bing.com", "yahoo.com", "adobe.com",
    "wordpress.com", "mozilla.org", "debian.org", "ubuntu.com", "archlinux.org",
    "kernel.org", "rust-lang.org", "crates.io", "docker.com", "npmjs.com",
    "pypi.org", "gitlab.com", "bitbucket.org", "atlassian.com", "salesforce.com",
    "oracle.com", "ibm.com", "intel.com", "nvidia.com", "amd.com",
]


def synth_domains(rng, count, existing):
    """Synthesise `count` unique domains that look like real hostnames."""
    out = []
    while len(out) < count:
        body = rng.choice(BODY_WORDS)
        head = rng.choice(HEAD_WORDS)
        tld = rng.choice(TLDS)
        n = rng.randrange(1, 100000)
        base = f"{head}{n}-{body}.{tld}"
        # Roughly a third get an extra label. Deeper names are what wildcard
        # rules are supposed to catch, so the shape matters for scenario B.
        if rng.random() < 0.33:
            base = f"{rng.choice(SUBDOMAIN_PREFIXES)}.{base}"
        if base in existing:
            continue
        existing.add(base)
        out.append(base)
    return out


def synth_ptr_names(rng, count):
    """Reverse names for public IPv4 space only."""
    seen = set()
    out = []
    while len(out) < count:
        a = rng.choice(PUBLIC_FIRST_OCTETS)
        b, c, d = rng.randrange(256), rng.randrange(256), rng.randrange(1, 255)
        name = f"{d}.{c}.{b}.{a}.in-addr.arpa"
        if name in seen:
            continue
        seen.add(name)
        out.append(name)
    return out


def zipf_cum_weights(size, alpha):
    """Cumulative weights for a Zipf(alpha) distribution over `size` ranks."""
    cum = []
    total = 0.0
    for rank in range(1, size + 1):
        total += 1.0 / (rank ** alpha)
        cum.append(total)
    return cum, total


def pick_blocked(rng, domains, cum, total, target_share, protected):
    """
    Choose which domains are blocked so the realised share of the *stream* that
    hits a blocked domain lands near `target_share`.

    Real ad/tracker domains are not the head of the distribution — nobody blocks
    google.com — so the head seeded from REAL_HEAD_DOMAINS is protected and
    candidates are walked in a seeded random order, accumulating probability
    mass until the target is reached.
    """
    probs = []
    prev = 0.0
    for c in cum:
        probs.append((c - prev) / total)
        prev = c

    candidates = [i for i, d in enumerate(domains) if d not in protected]
    rng.shuffle(candidates)

    blocked = set()
    mass = 0.0
    for i in candidates:
        if mass >= target_share:
            break
        blocked.add(i)
        mass += probs[i]
    return blocked, mass


def main():
    p = argparse.ArgumentParser(
        description="Generate a Zipf-distributed dnsperf dataset with churn.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--unique", type=int, default=150000,
                   help="size of the recurring (Zipf) working set. Deliberately "
                        "above the 100k L1 block-decision cache so eviction runs.")
    p.add_argument("--zipf", type=float, default=0.9, help="Zipf alpha")
    p.add_argument("--lines", type=int, default=2000000,
                   help="total query lines emitted")
    p.add_argument("--churn", type=float, default=10.0,
                   help="percent of the stream drawn from a single-occurrence "
                        "cold-tail pool")
    p.add_argument("--block-rate", type=float, default=25.0,
                   help="percent of the stream that should hit a blocked domain")
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--out", default="data/queries-realistic.txt")
    args = p.parse_args()

    if not 0 <= args.churn < 100:
        p.error("--churn must be in [0, 100)")
    if not 0 <= args.block_rate < 100:
        p.error("--block-rate must be in [0, 100)")

    rng = random.Random(args.seed)
    out_path = os.path.abspath(args.out)
    out_dir = os.path.dirname(out_path)
    os.makedirs(out_dir, exist_ok=True)

    n_ptr = int(args.lines * PTR_SHARE)
    n_cold = int(args.lines * args.churn / 100.0)
    n_hot = args.lines - n_ptr - n_cold
    if n_hot <= 0:
        p.error("--churn leaves no room for the recurring working set")

    print(f"[gen] working set {args.unique} unique, "
          f"{n_hot} hot lines / {n_cold} cold lines / {n_ptr} PTR lines",
          file=sys.stderr)

    # ── populations ──────────────────────────────────────────────────────────
    taken = set()
    hot = list(REAL_HEAD_DOMAINS)[: args.unique]
    taken.update(hot)
    if len(hot) < args.unique:
        hot += synth_domains(rng, args.unique - len(hot), taken)

    cold = synth_domains(rng, n_cold, taken) if n_cold else []
    ptr_names = synth_ptr_names(rng, max(n_ptr, 1)) if n_ptr else []

    cum, total = zipf_cum_weights(len(hot), args.zipf)

    # ── which domains are blocked ────────────────────────────────────────────
    target = args.block_rate / 100.0
    protected = set(REAL_HEAD_DOMAINS)
    blocked_idx, hot_mass = pick_blocked(rng, hot, cum, total, target, protected)
    blocked_hot = {hot[i] for i in blocked_idx}
    # The cold tail is blocked at the same rate, so churn does not dilute the
    # block rate as the stream advances.
    n_cold_blocked = int(len(cold) * target)
    blocked_cold = set(cold[:n_cold_blocked])

    # ── build the stream ─────────────────────────────────────────────────────
    print("[gen] sampling Zipf stream...", file=sys.stderr)
    forward_names = random.Random(args.seed + 1).choices(
        hot, cum_weights=cum, k=n_hot
    )
    forward_names.extend(cold)

    type_pop = [t for t, _ in FORWARD_TYPE_WEIGHTS]
    type_cum = []
    acc = 0.0
    for _, w in FORWARD_TYPE_WEIGHTS:
        acc += w
        type_cum.append(acc)
    types = random.Random(args.seed + 2).choices(
        type_pop, cum_weights=type_cum, k=len(forward_names)
    )

    lines = [f"{n} {t}" for n, t in zip(forward_names, types)]
    if n_ptr:
        ptr_stream = random.Random(args.seed + 3).choices(ptr_names, k=n_ptr)
        lines.extend(f"{n} PTR" for n in ptr_stream)

    random.Random(args.seed + 4).shuffle(lines)

    # ── realised statistics (measured, not assumed) ──────────────────────────
    blocked_all = blocked_hot | blocked_cold
    type_counts = Counter(line.rsplit(" ", 1)[1] for line in lines)
    blocked_lines = sum(
        1 for line in lines if line.rsplit(" ", 1)[0] in blocked_all
    )
    realised_block_rate = 100.0 * blocked_lines / len(lines)

    # ── write ────────────────────────────────────────────────────────────────
    print(f"[gen] writing {len(lines)} lines to {out_path}", file=sys.stderr)
    with open(out_path, "w") as f:
        for i in range(0, len(lines), 100000):
            f.write("\n".join(lines[i:i + 100000]))
            f.write("\n")

    blocked_path = os.path.join(out_dir, "blocked-domains.txt")
    with open(blocked_path, "w") as f:
        f.write("\n".join(sorted(blocked_all)))
        f.write("\n")

    manifest = {
        "generator": "generate-queries.py",
        "params": {
            "unique": args.unique,
            "zipf_alpha": args.zipf,
            "lines": args.lines,
            "churn_percent": args.churn,
            "block_rate_percent": args.block_rate,
            "seed": args.seed,
        },
        "realised": {
            "total_lines": len(lines),
            "unique_hot_domains": len(hot),
            "unique_cold_domains": len(cold),
            "unique_ptr_names": len(ptr_names),
            "unique_names_total": len(hot) + len(cold) + len(ptr_names),
            "blocked_domains": len(blocked_all),
            "block_rate_percent": round(realised_block_rate, 3),
            "zipf_mass_on_blocked_hot": round(100.0 * hot_mass, 3),
            "type_mix_percent": {
                t: round(100.0 * c / len(lines), 3)
                for t, c in sorted(type_counts.items())
            },
        },
        "outputs": {
            "queries": out_path,
            "blocked_domains": blocked_path,
        },
        "notes": [
            "dnsperf loops the datafile, so the cold-tail pool is only genuinely "
            "cold within a single pass. Sustained pressure on the block decision "
            "cache comes from the working set exceeding its 100k L1, not from "
            "churn alone.",
            "PTR names are drawn from public IPv4 space only: ferrous-dns has "
            "block_private_ptr enabled by default, which would otherwise turn "
            "every PTR query into a block.",
        ],
    }
    manifest_path = out_path + ".manifest.json"
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)
        f.write("\n")

    r = manifest["realised"]
    print(f"[gen] {r['unique_names_total']} unique names, "
          f"block rate {r['block_rate_percent']}%, "
          f"types {r['type_mix_percent']}", file=sys.stderr)
    print(f"[gen] manifest: {manifest_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
