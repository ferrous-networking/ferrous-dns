/// Computes Shannon entropy in bits per character.
///
/// Uses a stack-allocated histogram `[u32; 256]` (~1 KB) — zero heap allocation.
#[inline]
pub fn shannon_entropy(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f32;
    let mut entropy: f32 = 0.0;
    for &count in &counts {
        if count > 0 {
            let p = count as f32 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Extracts the subdomain portion (everything before the apex domain).
///
/// Returns `None` if the domain has no subdomain (e.g. `example.com`).
/// Handles compound TLDs (e.g. `sub.example.co.uk` → `sub`).
/// Zero heap allocation: uses reverse byte scan like `extract_apex`.
pub fn extract_subdomain(domain: &str) -> Option<&str> {
    let apex = extract_apex(domain);
    if apex.len() >= domain.len() {
        return None;
    }
    // domain = "sub.example.com", apex = "example.com" → "sub"
    let prefix_len = domain.len() - apex.len() - 1; // -1 for the dot separator
    if prefix_len == 0 {
        return None;
    }
    Some(&domain[..prefix_len])
}

/// Common two-level TLDs where the apex requires 3 labels (e.g. `example.co.uk`).
///
/// This is a heuristic — not a full Public Suffix List. Covers the most common
/// compound TLDs to avoid grouping unrelated domains under a public suffix.
const COMPOUND_TLDS: &[&str] = &[
    "co.uk", "org.uk", "ac.uk", "gov.uk", "net.uk", "me.uk", "co.jp", "or.jp", "ne.jp", "ac.jp",
    "go.jp", "com.br", "org.br", "net.br", "gov.br", "edu.br", "com.au", "org.au", "net.au",
    "edu.au", "gov.au", "co.nz", "org.nz", "net.nz", "co.za", "org.za", "co.in", "org.in",
    "net.in", "gen.in", "com.cn", "org.cn", "net.cn", "gov.cn", "edu.cn", "com.tw", "org.tw",
    "com.hk", "org.hk", "com.sg", "org.sg", "com.my", "org.my", "co.kr", "or.kr", "co.il",
    "org.il", "com.ar", "org.ar", "com.mx", "org.mx", "com.co", "org.co", "com.ve", "com.pe",
    "com.tr", "org.tr", "co.th", "or.th", "com.ph", "org.ph", "com.ng", "org.ng", "co.ke", "or.ke",
    "com.eg", "org.eg", "com.pk", "org.pk", "com.bd", "org.bd",
];

/// Checks if the last two labels form a known compound TLD (e.g. `co.uk`).
fn is_compound_tld(domain: &str) -> bool {
    // Find the second-to-last dot to extract the last two labels
    let bytes = domain.as_bytes();
    let mut dot_count = 0;
    for (i, &b) in bytes.iter().enumerate().rev() {
        if b == b'.' {
            dot_count += 1;
            if dot_count == 2 {
                let last_two = &domain[i + 1..];
                return COMPOUND_TLDS
                    .iter()
                    .any(|tld| last_two.eq_ignore_ascii_case(tld));
            }
        }
    }
    // Fewer than 2 dots — check the entire domain if it has exactly 1 dot
    if dot_count == 1 {
        return COMPOUND_TLDS
            .iter()
            .any(|tld| domain.eq_ignore_ascii_case(tld));
    }
    false
}

/// Extracts the apex domain from a domain name.
///
/// For standard TLDs (e.g. `example.com`), returns the last 2 labels.
/// For known compound TLDs (e.g. `co.uk`), returns the last 3 labels.
pub fn extract_apex(domain: &str) -> &str {
    let target_dots = if is_compound_tld(domain) { 3 } else { 2 };
    let bytes = domain.as_bytes();
    let mut dot_count = 0;
    for (i, &b) in bytes.iter().enumerate().rev() {
        if b == b'.' {
            dot_count += 1;
            if dot_count == target_dots {
                return &domain[i + 1..];
            }
        }
    }
    domain
}
