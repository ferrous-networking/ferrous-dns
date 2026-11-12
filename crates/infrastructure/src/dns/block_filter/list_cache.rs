use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fmt::Write as _;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::warn;

const COPY_SUFFIX: &str = ".txt";
/// A copy being written; renamed over the copy once complete.
const PARTIAL_SUFFIX: &str = ".partial";

/// The last download of each list, kept on disk so a start compiles its lists
/// without the network. One file per URL, named by the URL's SHA-256, so a
/// URL that carries a token never becomes a file name.
///
/// Best-effort: an I/O error is logged and the build goes on without the file.
#[derive(Debug, Clone)]
pub struct ListCache {
    dir: PathBuf,
}

impl ListCache {
    /// The `lists` directory beside the database file at `database_path`,
    /// which is writable wherever SQLite can keep its WAL.
    pub fn beside_database(database_path: &str) -> Self {
        let parent = Path::new(database_path).parent().unwrap_or(Path::new(""));
        Self {
            dir: parent.join("lists"),
        }
    }

    fn path(&self, url: &str) -> PathBuf {
        let mut name = String::with_capacity(64 + COPY_SUFFIX.len());
        for byte in Sha256::digest(url.as_bytes()) {
            let _ = write!(name, "{byte:02x}");
        }
        name.push_str(COPY_SUFFIX);
        self.dir.join(name)
    }

    /// Whether any list was kept, by this run or an earlier one.
    pub async fn has_copies(&self) -> bool {
        let Ok(mut entries) = tokio::fs::read_dir(&self.dir).await else {
            return false;
        };
        while let Ok(Some(entry)) = entries.next_entry().await {
            if entry.file_name().to_str().is_some_and(is_copy) {
                return true;
            }
        }
        false
    }

    pub async fn read(&self, url: &str) -> Option<Arc<str>> {
        match tokio::fs::read_to_string(self.path(url)).await {
            Ok(text) => Some(Arc::from(text)),
            Err(e) if e.kind() == ErrorKind::NotFound => None,
            Err(e) => {
                warn!(url, error = %e, "Failed to read the copy of a list kept on disk");
                None
            }
        }
    }

    pub async fn write(&self, url: &str, text: &str) {
        let path = self.path(url);
        let mut partial = path.clone().into_os_string();
        partial.push(PARTIAL_SUFFIX);
        let written = async {
            tokio::fs::create_dir_all(&self.dir).await?;
            tokio::fs::write(&partial, text).await?;
            tokio::fs::rename(&partial, &path).await
        };
        if let Err(e) = written.await {
            warn!(
                url,
                dir = %self.dir.display(),
                error = %e,
                "Failed to keep a copy of a list on disk"
            );
        }
    }

    /// Deletes the copies of lists not in `urls`, and any copy an interrupted
    /// write left half done. Only names this cache writes are touched.
    pub async fn retain<'a>(&self, urls: impl Iterator<Item = &'a String>) {
        let keep: HashSet<PathBuf> = urls.map(|url| self.path(url)).collect();
        let Ok(mut entries) = tokio::fs::read_dir(&self.dir).await else {
            return;
        };
        while let Ok(Some(entry)) = entries.next_entry().await {
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            let path = entry.path();
            let unused = match name.strip_suffix(PARTIAL_SUFFIX) {
                Some(copy) => is_copy(copy),
                None => is_copy(&name) && !keep.contains(&path),
            };
            if unused {
                if let Err(e) = tokio::fs::remove_file(&path).await {
                    warn!(path = %path.display(), error = %e, "Failed to delete an unused list copy");
                }
            }
        }
    }
}

/// `<64 lowercase hex digits>.txt`, the name of a copy.
fn is_copy(name: &str) -> bool {
    name.strip_suffix(COPY_SUFFIX).is_some_and(|hash| {
        hash.len() == 64 && hash.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    })
}
