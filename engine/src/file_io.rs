use crate::header::{DBHeader, EncryptedDB, HEADER_LEN};
use fs2::FileExt;
use std::fs::{self, remove_file, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::{error::Error, fmt::{Display, Formatter}};
use sha2::{Digest, Sha512};

const DB_FILE: &str = "db.bin";
const DB_BAK_FILE: &str = "db.bin.bak";


#[derive(Debug)]
pub enum FileIOWarn {
    RevertedForUngracefulExited,
    ResetDBForCorruptedFile
}
impl Display for FileIOWarn {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            FileIOWarn::RevertedForUngracefulExited => {
                write!(f, "This app is ungracefully exited. reverted the database to the last backup")
            }
            FileIOWarn::ResetDBForCorruptedFile => {
                write!(f, "Reset the database, because the database file is corrupted.")
            }
        }
    }
}
#[derive(Debug)]
pub enum FileIOError {
    // Lock 관련
    LockUnavailable(io::Error),
    LockWouldBlock(io::Error),  // 다른 프로세스가 락 보유

    // 파일 열기/읽기/쓰기/동기화
    FileOpenFailed(io::Error),
    FileReadFailed(io::Error),
    FileWriteFailed(io::Error),
    FileSyncFailed(io::Error),
    FileRenameFailed(io::Error),
    FileDeleteFailed(io::Error),

    // 헤더/포맷 관련
    InvalidHeader,
    DBVersionMissMatch,

    // 무결성(재시도 이후에도 복원 불가)
    PersistentIntegrityFailure,
}
impl Display for FileIOError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        use FileIOError::*;
        match self {
            LockWouldBlock(e) => write!(f, "File is locked by another process: {}", e),
            LockUnavailable(e) => write!(f, "Failed to getting file lock: {}", e),
            FileOpenFailed(e) => write!(f, "Failed to open file: {}", e),
            FileReadFailed(e) => write!(f, "Failed to read file: {}", e),
            FileWriteFailed(e) => write!(f, "Failed to write file: {}", e),
            FileSyncFailed(e) => write!(f, "Failed to sync file: {}", e),
            FileRenameFailed(e) => write!(f, "Failed to rename file: {}", e),
            FileDeleteFailed(e) => write!(f, "Failed to delete file: {}", e),
            PersistentIntegrityFailure => write!(f, "Failed to write valid DB after retries"),
            InvalidHeader => write!(f, "Invalid DB header"),
            DBVersionMissMatch => write!(f, "Unsupported DB version"),
        }
    }
}
impl Error for FileIOError {}


pub fn load_db() -> Result<(Option<FileIOWarn>, DBHeader, Option<EncryptedDB>), FileIOError> {
    let bak_path = Path::new(DB_BAK_FILE);
    let db_path = Path::new(DB_FILE);

    let mut user_warn: Option<FileIOWarn> = None;

    let db_exist = fs::exists(db_path)
        .map_err(FileIOError::FileOpenFailed)?;
    let bak_exist = fs::exists(bak_path)
        .map_err(FileIOError::FileOpenFailed)?;

    if bak_exist {
        user_warn = Some(FileIOWarn::RevertedForUngracefulExited);

        if db_exist {
            fs::remove_file(db_path)
                .map_err(FileIOError::FileDeleteFailed)?;
        }
        fs::rename(bak_path, db_path)
            .map_err(FileIOError::FileRenameFailed)?;

    } else if !db_exist {
        return Ok( (None, DBHeader::empty_valid(), None) );
    }

    let db_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(db_path)
        .map_err(|err| FileIOError::FileOpenFailed(err))?;
    // match db_file.try_lock_exclusive() {
    //     Ok(()) => {}
    //     Err(err) if err.kind() == io::ErrorKind::WouldBlock => { return Err(FileIOError::LockWouldBlock(err)) },
    //     Err(err) => { return Err(FileIOError::LockUnavailable(err)) }
    // }
    let _ = db_file.unlock();
    if let Err(err) = db_file.try_lock_exclusive() {
        return Err(FileIOError::LockUnavailable(err));
    };

    let read_trials = 3;
    for _ in 0..read_trials {
        let mut data = Vec::new();
        (&db_file).seek(SeekFrom::Start(0)).map_err(|e| FileIOError::FileReadFailed(e))?;
        (&db_file).take(u64::MAX).read_to_end(&mut data)
            .map_err(|err| FileIOError::FileReadFailed(err))?;
        (&db_file).seek(SeekFrom::Start(0)).map_err(|e| FileIOError::FileReadFailed(e))?;
        let (header, ciphertext) = match DBHeader::parse_header(data.as_slice()) {
            Ok(v) => v,
            Err(FileIOError::InvalidHeader) => {
                return Ok( (Some(FileIOWarn::ResetDBForCorruptedFile), DBHeader::empty_valid(), None) )
            }
            Err(err) => return Err(err)
        };
        let hash = Sha512::digest(ciphertext.as_slice());
        if header.ciphertext_checksum.as_slice() != hash.as_slice() {
            continue;
        }

        return Ok( (user_warn, header, Some(ciphertext) ) )
    }

    Ok( (Some(FileIOWarn::ResetDBForCorruptedFile), DBHeader::empty_valid(), None) )
}

pub fn save_db(header: &mut DBHeader, ciphertext: EncryptedDB) -> Result<(), FileIOError> {
    let db_path = Path::new(DB_FILE);
    let bak_path = Path::new(DB_BAK_FILE);

    let db_exists = fs::exists(db_path)
        .map_err(FileIOError::FileReadFailed)?;
    let bak_exists = fs::exists(bak_path)
        .map_err(FileIOError::FileReadFailed)?;

    if db_exists {
        if bak_exists {
            remove_file(db_path)
                .map_err(FileIOError::FileDeleteFailed)?;
        } else {
            fs::rename(db_path, bak_path)
                .map_err(FileIOError::FileRenameFailed)?;
        }
    }

    let mut db_file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(db_path)
        .map_err(|err| FileIOError::FileOpenFailed(err))?;

    // if db_file.set_len(db_file.metadata().map_err(|err| FileIOError::FileReadFailed(err))?
    //         .len()).map_err(|err| FileIOError::FileWriteFailed(err)).is_err() {
    let _ = db_file.unlock();
    if let Err(err) = db_file.try_lock_exclusive() {
        return Err(FileIOError::LockUnavailable(err));
    };

    header.ciphertext_checksum = Sha512::digest(&ciphertext).into();
    header.ciphertext_len = ciphertext.len();

    let mut bytes = Vec::with_capacity(HEADER_LEN + header.ciphertext_len);
    header.write_to(&mut bytes);
    bytes.extend(ciphertext);

    let write_trials = 2;
    let check_counters = 3;
    let mut write_success= false;
    for _ in 0..write_trials {
        // db_file.set_len(0)
        //     .map_err(|err| FileIOError::FileWriteFailed(err))?;
        db_file.write_all(bytes.as_slice())
            .map_err(|err| FileIOError::FileWriteFailed(err))?;
        db_file.seek(SeekFrom::Start(0))
            .map_err(|err| FileIOError::FileWriteFailed(err))?;
        db_file.sync_all()
            .map_err(|err| FileIOError::FileSyncFailed(err))?;
        db_file.seek(SeekFrom::Start(0))
            .map_err(|err| FileIOError::FileWriteFailed(err))?;

        for _ in 0..check_counters {
            let file_len = db_file.metadata()
                .map_err(|err| FileIOError::FileReadFailed(err))?
                .len();
            if file_len as usize == bytes.len() {
                let mut file_reading = Vec::with_capacity(bytes.len());
                (&db_file).take(u64::MAX).read_to_end(&mut file_reading)
                    .map_err(|err| FileIOError::FileReadFailed(err))?;
                db_file.seek(SeekFrom::Start(0))
                    .map_err(|err| FileIOError::FileReadFailed(err))?;
                if bytes == file_reading {
                    write_success = true;
                    continue;
                } else {
                    write_success = false;
                    break;
                }
            }
        }
        if write_success {
            break;
        }
    }
    if write_success == false {
        return Err(FileIOError::PersistentIntegrityFailure);
    }

    match fs::exists(bak_path) {
        Ok(true) => {
            fs::remove_file(bak_path)
                .map_err(|err| FileIOError::FileDeleteFailed(err))?;
        }
        Ok(false) => {}
        Err(err) => {
            return Err(FileIOError::FileReadFailed(err));
        }
    }

    Ok( () )
}

pub fn mark_as_ungraceful_exited_to_file() -> Result<(), FileIOError> {
    let db_path = Path::new(DB_FILE);
    let bak_path = Path::new(DB_BAK_FILE);

    let db_exists = fs::exists(db_path)
        .map_err(FileIOError::FileReadFailed)?;
    let bak_exists = fs::exists(bak_path)
        .map_err(FileIOError::FileReadFailed)?;

    if bak_exists {
        return Ok( () );
    }

    if db_exists {
        fs::rename(db_path, bak_path)
            .map_err(FileIOError::FileRenameFailed)?;
    } else {
        File::create_new(bak_path)
            .map_err(FileIOError::FileWriteFailed)?;
    }

    Ok( () )
}

pub fn mark_as_graceful_exited_to_file() -> Result<(), FileIOError> {
    let db_path = Path::new(DB_FILE);
    let bak_path = Path::new(DB_BAK_FILE);

    let db_exists = fs::exists(db_path)
        .map_err(FileIOError::FileReadFailed)?;
    let bak_exists = fs::exists(bak_path)
        .map_err(FileIOError::FileReadFailed)?;

    if db_exists && bak_exists {
        remove_file(db_path)
            .map_err(FileIOError::FileDeleteFailed)?;

        fs::rename(bak_path, db_path)
            .map_err(FileIOError::FileRenameFailed)?;
    } else if !db_exists && bak_exists {
        fs::rename(bak_path, db_path)
            .map_err(FileIOError::FileRenameFailed)?;
    }

    Ok(())
}
