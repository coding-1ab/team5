use std::{error::Error, fmt::{Display, Formatter}};
use fs2::FileExt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use crate::header::{CipherTextLen, DBHeader, EncAesKey, EncryptedDB, Nonce, HEADER_LEN}

const DB_FILE: &str = "db.bin";
const DB_FILE_OLD: &str = "db.bin.old";


#[derive(Debug)]
pub enum FileIOError {
    // Lock 관련
    LockUnavailable, // 다른 프로세스가 락 보유

    // 파일 열기/읽기/쓰기/동기화
    FileOpenFailed(io::Error),
    FileReadFailed(io::Error),
    FileWriteFailed(io::Error),
    FileSyncFailed(io::Error),

    // 헤더/포맷 관련
    InvalidHeader,
    UnsupportedVersion,

    // 백업 관련
    DBBackupRenameFailed(io::Error),
    DBBackupDeleteFailed(io::Error),

    // 무결성(재시도 이후에도 복원 불가)
    PersistentIntegrityFailure,
}

impl std::fmt::Display for FileIOError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use FileIOError::*;
        match self {
            LockUnavailable => write!(f, "File is locked by another process"),
            FileOpenFailed(e) => write!(f, "Failed to open file: {}", e),
            FileReadFailed(e) => write!(f, "Failed to read file: {}", e),
            FileWriteFailed(e) => write!(f, "Failed to write file: {}", e),
            FileSyncFailed(e) => write!(f, "Failed to sync file: {}", e),
            DBBackupRenameFailed(e) => write!(f, "Failed to create DB backup (rename): {}", e),
            DBBackupDeleteFailed(e) => write!(f, "Failed to delete DB backup: {}", e),
            PersistentIntegrityFailure => write!(f, "Failed to write valid DB after retries"),
        }
    }
}

impl std::error::Error for FileIOError {}

/// LockFile: 프로그램이 보유하는 락 소유권 객체.
/// - db_fd: 항상 Some(File) — db 파일(바로 열 수 있도록)
/// - old_fd: Option<File> — old 파일을 잠근 경우에만 Some
pub struct LockFile {
    db_fd: File,
    old_fd: Option<File>,
    db_path: PathBuf,
    old_path: PathBuf,
}

impl LockFile {
    /// 획득: db_path가 없으면 생성(create true). old_path가 존재하면 먼저 old를 열어 락을 걸고 나서 db 락을 시도.
    /// 락 실패 시 `LockUnavailable` 반환.
    pub fn acquire(db_path: &Path, old_path: &Path) -> Result<Self, FileIOError> {
        // If old exists, open it and lock first (to respect lock ordering)
        let old_exists = old_path.exists();

        let mut old_fd_opt: Option<File> = None;

        if old_exists {
            // open old for read+write (we may delete it later on success)
            let old_fd = OpenOptions::new()
                .read(true)
                .write(true)
                .open(old_path)
                .map_err(FileIOError::FileOpenFailed)?;

            // try exclusive lock (non-blocking). If it fails, return LockUnavailable
            if let Err(_) = old_fd.try_lock_exclusive() {
                return Err(FileIOError::LockUnavailable);
            }
            old_fd_opt = Some(old_fd);
        }

        // Open (or create) db file
        let db_fd = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(db_path)
            .map_err(FileIOError::FileOpenFailed)?;

        if let Err(_) = db_fd.try_lock_exclusive() {
            // unlocking old if we locked it will happen on drop of old_fd_opt
            return Err(FileIOError::LockUnavailable);
        }

        Ok(LockFile {
            db_fd,
            old_fd: old_fd_opt,
            db_path: db_path.to_path_buf(),
            old_path: old_path.to_path_buf(),
        })
    }

    /// 내부적으로 보유한 경로 반환 (참고용)
    pub fn db_path(&self) -> &Path {
        &self.db_path
    }
    pub fn old_path(&self) -> &Path {
        &self.old_path
    }
}

// Drop will release locks by dropping File objects; fs2::FileExt::unlock will be attempted implicitly on drop
impl Drop for LockFile {
    fn drop(&mut self) {
        // best-effort unlock; ignore errors
        let _ = self.db_fd.unlock();
        if let Some(ref old) = self.old_fd {
            let _ = old.unlock();
        }
    }
}


pub fn load_or_init_db()
        -> Result<(
            bool, Nonce, Nonce, EncAesKey, CipherTextLen, EncryptedDB,
            LockFile
        ), FileIOError> {
    let db_path = Path::new(DB_FILE);
    let old_path = Path::new(DB_FILE_OLD);

    // Acquire locks: old first if exists (lock ordering)
    let lock = LockFile::acquire(db_path, old_path)?;

    // Decide which file to use for loading: if old exists, use old (per invariant)
    let target_path = if lock.old_fd.is_some() {
        &lock.old_path
    } else {
        &lock.db_path
    };

    // Ensure file exists: acquire already created db file if absent; but old may exist or not
    // Read file metadata
    let meta = fs::metadata(target_path).map_err(FileIOError::FileReadFailed)?;

    let file_len = meta.len() as usize;

    if file_len == 0 {
        // First login / empty DB
        return Ok((true,
                   Nonce::default(), Nonce::default(), EncAesKey{}, 0, Vec::new(), lock
        ));
    }

    // Read whole file bytes
    let bytes = fs::read(target_path).map_err(FileIOError::FileReadFailed)?;

    // Parse header / Split ciphertext
    let (header,ciphertext) = DBHeader::parse_header(bytes.as_slice())?;
    ///TODO///////////////////////////
    Ok( (false, header.db_nonce, header.user_nonce, header.enc_aes_key, header.ciphertext_len, ciphertext, lock) )
}


pub fn save_db(
    lock: &LockFile,
    header: DBHeader,
    mut ciphertext: EncryptedDB,
) -> Result<(), FileIOError> {
    let db_path = &lock.db_path;
    let old_path = &lock.old_path;

    // ### if db exists and old does not exist -> create backup by rename
    let db_exists = db_path.exists();
    let old_exists = old_path.exists();

    if db_exists && !old_exists {
        fs::rename(db_path, old_path).map_err(FileIOError::DBBackupRenameFailed)?;
        // After rename, db_path may not exist; we'll create/truncate below
    }

    // Attempt up to N tries in case of integrity mismatch
    let max_attempts = 3usize;
    for attempt in 0..max_attempts {
        // ### open (or create) db_path for write
        let mut file = OpenOptions::new()
            .write(true)
            .read(true)
            .create(true)
            .open(db_path)
            .map_err(FileIOError::FileOpenFailed)?;

        // Truncate to zero
        file.set_len(0).map_err(FileIOError::FileWriteFailed)?;
        file.seek(SeekFrom::Start(0))
            .map_err(FileIOError::FileWriteFailed)?;

        // Write header + ciphertext
        let mut bytes = Vec::with_capacity(HEADER_LEN + header.ciphertext_len);
        header.write_to(&mut bytes);
        bytes.append(&mut ciphertext);
        file.write_all(bytes.as_slice())
            .map_err(FileIOError::FileWriteFailed)?;

        // Sync to disk
        file.sync_all()
            .map_err(FileIOError::FileSyncFailed)?;

        // Verify by comparing expected length to actual file length
        let expected_len = HEADER_LEN + header.ciphertext_len;
        let actual_len = file.metadata().map_err(FileIOError::FileReadFailed)?.len() as usize;
///TODO//////////////////////////////////////////////////
        if actual_len == expected_len {
            // Success: attempt to remove old backup (if exists)
            if old_path.exists() {
                if let Err(e) = fs::remove_file(old_path) {
                    // return failure to caller with specific error
                    return Err(FileIOError::DBBackupDeleteFailed(e));
                }
            }
            return Ok(());
        } else {
            // Integrity failed — try again unless we exhausted attempts.
            if attempt + 1 >= max_attempts {
                return Err(FileIOError::PersistentIntegrityFailure);
            }
            // else continue to retry
        }
    }

    // unreachable due to return in loop, but keep as safeguard
    Err(FileIOError::PersistentIntegrityFailure)
}


// pub fn graceful_exit() {
//     process::exit(0);
// }
//

