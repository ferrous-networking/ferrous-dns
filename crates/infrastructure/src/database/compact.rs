//! Offline compaction: rewrites the database file without its free pages.

use super::base_options;
use ferrous_dns_domain::DomainError;
use sqlx::sqlite::SqliteLockingMode;
use sqlx::{ConnectOptions, Connection, SqliteConnection};
use std::ffi::OsString;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// How long compaction waits for another process to let go of the database.
const BUSY_TIMEOUT: Duration = Duration::from_secs(2);

const IN_USE: &str = "the database is in use; stop the server before compacting it";

/// File sizes around a compaction, in bytes; `bytes_before` includes a leftover WAL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompactionReport {
    pub bytes_before: u64,
    pub bytes_after: u64,
}

fn db_err(e: sqlx::Error) -> DomainError {
    DomainError::DatabaseError(e.to_string())
}

fn io_err(e: std::io::Error) -> DomainError {
    DomainError::IoError(e.to_string())
}

/// SQLITE_BUSY in any of its extended forms: another connection holds the lock.
fn is_busy(e: &sqlx::Error) -> bool {
    e.as_database_error()
        .and_then(|d| d.code())
        .and_then(|code| code.parse::<i32>().ok())
        .is_some_and(|code| code & 0xff == 5)
}

fn lock_err(e: sqlx::Error) -> DomainError {
    if is_busy(&e) {
        DomainError::DatabaseError(IN_USE.to_string())
    } else {
        db_err(e)
    }
}

fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut name: OsString = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

fn file_len(path: &Path) -> u64 {
    fs::metadata(path).map_or(0, |m| m.len())
}

fn remove_if_present(path: &Path) -> Result<(), DomainError> {
    match fs::remove_file(path) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(io_err(e)),
        _ => Ok(()),
    }
}

/// Rewrites the database without its free pages and with incremental auto-vacuum, so a
/// file created before auto-vacuum shrinks to its live data and gives pages back from
/// then on.
///
/// `VACUUM INTO` writes the copy next to the database, which needs free disk for the
/// live data only and leaves the original untouched until the copy is on disk. The
/// connection takes an exclusive lock first: a running server keeps the database open,
/// so the lock fails and nothing changes.
pub async fn compact_database(database_url: &str) -> Result<CompactionReport, DomainError> {
    let options = base_options(database_url)
        .map_err(db_err)?
        .create_if_missing(false)
        .locking_mode(SqliteLockingMode::Exclusive)
        .busy_timeout(BUSY_TIMEOUT)
        // Waiting out the lock and the copy itself are slow by design, not worth a warning.
        .disable_statement_logging();
    let path = options.get_filename().to_path_buf();
    let wal = sibling(&path, "-wal");
    let copy = sibling(&path, ".compact");
    let bytes_before = file_len(&path) + file_len(&wal);

    // Left by an interrupted run; VACUUM INTO refuses an existing target.
    remove_if_present(&copy)?;

    let mut conn = SqliteConnection::connect_with(&options)
        .await
        .map_err(lock_err)?;
    let written = write_copy(&mut conn, &copy).await;
    // Closing folds the WAL back into the original and deletes it.
    let closed = conn.close().await.map_err(db_err);
    if let Err(e) = written
        .and(closed)
        .and_then(|()| replace(&path, &wal, &copy))
    {
        let _ = fs::remove_file(&copy);
        return Err(e);
    }

    Ok(CompactionReport {
        bytes_before,
        bytes_after: file_len(&path),
    })
}

async fn write_copy(conn: &mut SqliteConnection, copy: &Path) -> Result<(), DomainError> {
    // In exclusive locking mode the first write takes the file lock and keeps it until
    // the connection closes.
    sqlx::query("BEGIN EXCLUSIVE")
        .execute(&mut *conn)
        .await
        .map_err(lock_err)?;
    sqlx::query("COMMIT")
        .execute(&mut *conn)
        .await
        .map_err(db_err)?;

    let target = copy
        .to_str()
        .ok_or_else(|| DomainError::IoError(format!("non-UTF-8 path: {}", copy.display())))?;
    sqlx::query("VACUUM INTO ?")
        .bind(target)
        .execute(&mut *conn)
        .await
        .map_err(db_err)?;
    Ok(())
}

/// Puts the copy in place of the original once both are settled on disk. SQLite does not
/// sync a `VACUUM INTO` target, so the copy is synced before the rename and the directory
/// after it.
fn replace(path: &Path, wal: &Path, copy: &Path) -> Result<(), DomainError> {
    if file_len(wal) > 0 {
        return Err(DomainError::DatabaseError(format!(
            "{} was not folded back into the database; nothing was replaced",
            wal.display()
        )));
    }
    File::open(copy)
        .and_then(|f| f.sync_all())
        .map_err(io_err)?;
    let permissions = fs::metadata(path).map_err(io_err)?.permissions();
    fs::set_permissions(copy, permissions).map_err(io_err)?;
    fs::rename(copy, path).map_err(io_err)?;

    let dir = match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    };
    File::open(dir).and_then(|d| d.sync_all()).map_err(io_err)?;
    // A shared-memory index left by a killed server describes the old file.
    remove_if_present(&sibling(path, "-shm"))
}
