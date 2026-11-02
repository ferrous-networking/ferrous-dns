//! Lexical domain-name heuristics shared by the hot-path DGA guard and the
//! background DGA and tunneling detectors. Pure and allocation-free.

/// Shannon entropy in bits per byte.
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
    // Walks the input again rather than all 256 buckets: a label is at most
    // 63 bytes, and this runs on every cache hit. Taking each count zeroes it,
    // so a repeated byte adds its share once.
    for &b in data {
        let count = std::mem::take(&mut counts[b as usize]);
        if count > 0 {
            let p = count as f32 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// (consonants, vowels, digits, total bytes) of an SLD. Hyphens and other
/// bytes count only toward the total.
pub fn char_ratios(sld: &str) -> (u32, u32, u32, u32) {
    let mut consonants = 0u32;
    let mut vowels = 0u32;
    let mut digits = 0u32;
    let mut total = 0u32;

    for &b in sld.as_bytes() {
        total += 1;
        match b.to_ascii_lowercase() {
            b'a' | b'e' | b'i' | b'o' | b'u' => vowels += 1,
            b'b'..=b'd' | b'f'..=b'h' | b'j'..=b'n' | b'p'..=b't' | b'v'..=b'z' => {
                consonants += 1;
            }
            b'0'..=b'9' => digits += 1,
            _ => {}
        }
    }

    (consonants, vowels, digits, total)
}

/// Common two-level public suffixes whose apex takes three labels. A heuristic,
/// not the Public Suffix List: it only keeps unrelated domains from being
/// grouped under the most common compound suffixes.
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

/// Whether the last two labels of `domain` form a known compound suffix.
fn is_compound_tld(domain: &str) -> bool {
    // Every compound suffix ends in a two-letter country code, so `.com`,
    // `.net` and the like skip the list.
    if domain.rsplit('.').next().map_or(0, str::len) != 2 {
        return false;
    }
    let mut dot_count = 0;
    for (i, &b) in domain.as_bytes().iter().enumerate().rev() {
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
    dot_count == 1
        && COMPOUND_TLDS
            .iter()
            .any(|tld| domain.eq_ignore_ascii_case(tld))
}

/// The registrable part of `domain`: its last two labels, or three under a
/// compound suffix such as `co.uk`. Case is preserved.
pub fn extract_apex(domain: &str) -> &str {
    let target_dots = if is_compound_tld(domain) { 3 } else { 2 };
    let mut dot_count = 0;
    for (i, &b) in domain.as_bytes().iter().enumerate().rev() {
        if b == b'.' {
            dot_count += 1;
            if dot_count == target_dots {
                return &domain[i + 1..];
            }
        }
    }
    domain
}
