use std::fmt::{Display, Formatter};
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process;


const DB_FILE: &str = "db.bin";
const DB_FILE_OLD: &str = "db_old.bin";

#[derive(Debug, Eq, PartialEq)]
pub enum FileError {
    DatabaseMissing,
    IoRead,
    IoWrite,
    IoRename,
    IoDelete,
}

impl Display for FileError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            FileError::DatabaseMissing =>
                f.write_str("Database file does not exist"),
            FileError::IoRead =>
                f.write_str("Failed to read database file"),
            FileError::IoWrite =>
                f.write_str("Failed to write database file"),
            FileError::IoRename =>
                f.write_str("Failed to replace database file"),
            FileError::IoDelete =>
                f.write_str("Failed to remove old database backup"),
        }
    }
}

/// Load encrypted DB file as raw bytes.
/// Policy:
/// - If `db_old.bin` exists, ALWAYS use it
/// - Else if `db.bin` exists, use it
/// - Else -> DatabaseMissing
pub fn load_db() -> Result<Vec<u8>, FileError> {
    let old_path = Path::new(DB_FILE_OLD);
    let path = Path::new(DB_FILE);

    if old_path.exists() {
        return fs::read(old_path).map_err(|_| FileError::IoRead);
    }

    if path.exists() {
        return fs::read(path).map_err(|_| FileError::IoRead);
    }

    Err(FileError::DatabaseMissing)
}

/// Save encrypted DB atomically.
/// This function can be called:
/// - during program execution (manual backup)
/// - right before program exit
/// Algorithm:
/// 1. If `db.bin` exists -> rename to `db_old.bin`
/// 2. Write new `db.bin`
/// 3. Remove `db_old.bin`
pub fn save_db(data: &[u8]) -> Result<(), FileError> {
    let path = Path::new(DB_FILE);
    let old_path = Path::new(DB_FILE_OLD);

    // Step 1: move current db to backup
    if path.exists() {
        if old_path.exists() {
            fs::remove_file(old_path).map_err(|_| FileError::IoDelete)?;
        }

        fs::rename(path, old_path).map_err(|_| FileError::IoRename)?;
    }

    // Step 2: write new db
    {
        let mut file = fs::File::create(path).map_err(|_| FileError::IoWrite)?;
        file.write_all(data).map_err(|_| FileError::IoWrite)?;
        file.sync_all().map_err(|_| FileError::IoWrite)?;
    }

    // Step 3: remove backup
    if old_path.exists() {
        fs::remove_file(old_path).map_err(|_| FileError::IoDelete)?;
    }

    Ok(())
}

pub fn graceful_exit() {

    process::exit(0);
}
