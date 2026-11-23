use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_FILE: AtomicU64 = AtomicU64::new(0);

/// Creates an empty, writable config file in the temp dir and returns its path.
/// Tests run in parallel in one process, so the name carries a counter, not
/// the clock: two tests can read the same clock tick, and one then loads the
/// file the other wrote.
pub fn empty_config_file(prefix: &str) -> String {
    let path = std::env::temp_dir()
        .join(format!(
            "{prefix}_{}_{}.toml",
            std::process::id(),
            NEXT_FILE.fetch_add(1, Ordering::Relaxed)
        ))
        .to_string_lossy()
        .into_owned();
    std::fs::write(&path, "").unwrap();
    path
}
