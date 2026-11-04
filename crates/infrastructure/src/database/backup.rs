//! Online backup: a consistent copy of the database taken while the server writes to it.

use super::{base_options, db_err, io_err, remove_if_present, sibling, sync_parent_dir};
use ferrous_dns_domain::DomainError;
use sqlx::sqlite::SqliteConnectOptions;
use sqlx::{ConnectOptions, Connection, Row, SqliteConnection};
use std::fs::{self, File, OpenOptions};
use std::io::ErrorKind;
use std::path::Path;
use std::time::Duration;

/// How long the copy waits for a lock another connection holds.
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// Size of a finished backup, in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackupReport {
    pub bytes: u64,
}

fn already_exists(target: &Path) -> DomainError {
    DomainError::IoError(format!(
        "{} already exists; a backup never overwrites a file",
        target.display()
    ))
}

/// Copies the database at `database_url` to `target`, which must not exist yet.
///
/// `VACUUM INTO` reads the database in one read transaction, so the copy is the
/// state at one instant even while the server keeps writing, and it holds no lock
/// that would stall those writes. It goes to `<target>.partial`, created owner-only
/// first because the file holds the users, sessions and query log, and only an
/// `integrity_check` that passes gives it the name `target`: a failed or interrupted
/// run never leaves a file under the name a restore would pick.
pub async fn backup_database(
    database_url: &str,
    target: &Path,
) -> Result<BackupReport, DomainError> {
    // symlink_metadata: a dangling symlink is a name too.
    if fs::symlink_metadata(target).is_ok() {
        return Err(already_exists(target));
    }
    let partial = sibling(target, ".partial");
    // Left by an interrupted run; VACUUM INTO only writes into an empty file.
    remove_if_present(&partial)?;
    create_private(&partial)?;

    let result = async {
        write_copy(database_url, &partial).await?;
        finish(&partial, target).await
    }
    .await;
    if result.is_err() {
        let _ = fs::remove_file(&partial);
    }
    result
}

fn create_private(path: &Path) -> Result<(), DomainError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(path).map(drop).map_err(|e| io_err(path, e))
}

async fn write_copy(database_url: &str, partial: &Path) -> Result<(), DomainError> {
    let options = base_options(database_url)
        .map_err(db_err)?
        .create_if_missing(false)
        .busy_timeout(BUSY_TIMEOUT)
        .disable_statement_logging();
    let mut conn = SqliteConnection::connect_with(&options)
        .await
        .map_err(db_err)?;
    let target = partial
        .to_str()
        .ok_or_else(|| DomainError::IoError(format!("non-UTF-8 path: {}", partial.display())))?;
    let copied = sqlx::query("VACUUM INTO ?")
        .bind(target)
        .execute(&mut conn)
        .await
        .map(drop)
        .map_err(db_err);
    let closed = conn.close().await.map_err(db_err);
    copied.and(closed)
}

/// Syncs and checks the copy, then gives it its final name. SQLite does not sync a
/// `VACUUM INTO` target. A hard link fails when the name was taken meanwhile, where a
/// rename would replace it.
async fn finish(partial: &Path, target: &Path) -> Result<BackupReport, DomainError> {
    File::open(partial)
        .and_then(|f| f.sync_all())
        .map_err(|e| io_err(partial, e))?;
    check_integrity(partial).await?;
    match fs::hard_link(partial, target) {
        Ok(()) => remove_if_present(partial)?,
        Err(e) if e.kind() == ErrorKind::AlreadyExists => return Err(already_exists(target)),
        // A file system without hard links (FAT, some network shares): a rename
        // right after the name is checked again is the closest it offers.
        Err(_) if fs::symlink_metadata(target).is_err() => {
            fs::rename(partial, target).map_err(|e| io_err(target, e))?
        }
        Err(e) => return Err(io_err(target, e)),
    }
    sync_parent_dir(target)?;
    let bytes = fs::metadata(target).map_err(|e| io_err(target, e))?.len();
    Ok(BackupReport { bytes })
}

async fn check_integrity(path: &Path) -> Result<(), DomainError> {
    let options = SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(false)
        .disable_statement_logging();
    let mut conn = SqliteConnection::connect_with(&options)
        .await
        .map_err(db_err)?;
    let verdict = sqlx::query("PRAGMA integrity_check")
        .fetch_all(&mut conn)
        .await
        .map_err(db_err);
    let closed = conn.close().await.map_err(db_err);
    let rows = verdict?;
    closed?;
    let lines = rows
        .iter()
        .map(|row| row.try_get::<String, _>(0).map_err(db_err))
        .collect::<Result<Vec<_>, _>>()?;
    let problems: Vec<String> = lines.into_iter().filter(|line| line != "ok").collect();
    if problems.is_empty() {
        Ok(())
    } else {
        Err(DomainError::DatabaseError(format!(
            "the copy failed its integrity check: {}",
            problems.join("; ")
        )))
    }
}
