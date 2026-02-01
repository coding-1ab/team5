use crate::header::{DBHeader, EncryptedDB, HEADER_LEN};
use fs2::FileExt;
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::{error::Error, fmt::{Display, Formatter}};

const DB_FILE: &str = "db.bin";
const DB_BAK_FILE: &str = "db.bin.bak";


#[derive(Debug)]
pub enum FileIOWarn {
    RevertedForUngracefulExited,
    RevertedForCorruptedFile
}
impl Display for FileIOWarn {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            FileIOWarn::RevertedForUngracefulExited => {
                write!(f, "RevertedForUngracefulExited")
            }
            FileIOWarn::RevertedForCorruptedFile => {
                write!(f, "RevertedForCorruptedFile")
            }
        }
    }
}
#[derive(Debug)]
pub enum FileIOError {
    // Lock 관련
    LockUnavailable, // 다른 프로세스가 락 보유

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

    // 백업 관련
    // DBBackupDeleteFailed(io::Error),

    // 무결성(재시도 이후에도 복원 불가)
    PersistentIntegrityFailure,
}

impl Display for FileIOError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        use FileIOError::*;
        match self {
            LockUnavailable => write!(f, "File is locked by another process"),
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
pub fn load_db() ->
                 Result<(bool, Option<FileIOWarn>, DBHeader, Option<EncryptedDB>), FileIOError> {
    let bak_path = Path::new(DB_BAK_FILE);
    let db_path = Path::new(DB_FILE);

    let mut user_warn: Option<FileIOWarn> = None;

    let db_exist = match fs::exists(db_path) {
        Ok(true) => true,
        Ok(false) => false,
        Err(err) => {
            return Err(FileIOError::FileOpenFailed(err));
        }
    };
    let bak_exist = match fs::exists(bak_path) {
        Ok(true) => true,
        Ok(false) => false,
        Err(err) => {
            return Err(FileIOError::FileOpenFailed(err));
        }
    };

    let db_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(db_path)
        .map_err(|err| FileIOError::FileOpenFailed(err))?;
    match db_file.try_lock_exclusive() {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::WouldBlock => { /* 보유중 */ },
        Err(err) => { return Err(FileIOError::LockUnavailable) }
    }

    if bak_exist {
        user_warn = Some(FileIOWarn::RevertedForUngracefulExited);
        if db_exist {
            fs::remove_file(db_path)
                .map_err(|err| FileIOError::FileDeleteFailed(err))?;
        }
        fs::rename(bak_path, db_path).map_err(|err| FileIOError::FileRenameFailed(err))?;
    } else if !db_exist {
        return Ok( (true, None, DBHeader::empty_valid(), None) )
    }

    let read_triales = 3;
    for _ in 0..read_triales {
        let mut data = Vec::new();
        (&db_file).seek(SeekFrom::Start(0));
        (&db_file).take(u64::MAX).read_to_end(&mut data)
            .map_err(|err| FileIOError::FileReadFailed(err))?;
        (&db_file).seek(SeekFrom::Start(0));
        let (header, ciphertext) = match DBHeader::parse_header(data.as_slice()) {
            Ok(v) => v,
            Err(FileIOError::InvalidHeader) => {
                print!("~{}~", data.len());
                return Ok((true, Some(FileIOWarn::RevertedForCorruptedFile), DBHeader::empty_valid(), None))
            }
            Err(e) => return Err(e)
        };
        let hash = Sha256::digest(ciphertext.as_slice());
        if header.ciphertext_checksum != hash.as_slice() {
            continue;
        }

        return Ok( (false, user_warn, header, Some(ciphertext) ) )
    }

    Ok( (true, Some(FileIOWarn::RevertedForCorruptedFile), DBHeader::empty_valid(), None) )
}


pub fn save_db(mut header: DBHeader, mut ciphertext: EncryptedDB) -> Result<(), FileIOError> {
    let db_path = Path::new(DB_FILE);
    let bak_path = Path::new(DB_BAK_FILE);

    let mut db_file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(db_path)
        .map_err(|err| FileIOError::FileOpenFailed(err))?;

    // if db_file.set_len(db_file.metadata().map_err(|err| FileIOError::FileReadFailed(err))?
    //         .len()).map_err(|err| FileIOError::FileWriteFailed(err)).is_err() {
    let _ = db_file.unlock().ok();
    if db_file.try_lock_exclusive().is_err() {
        return Err(FileIOError::LockUnavailable);
    };
    // }

    let bak_file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(bak_path)
        .map_err(|err| FileIOError::FileOpenFailed(err))?;

    let _ = bak_file.unlock().ok();
    if bak_file.try_lock_exclusive().is_err() {
        return Err(FileIOError::LockUnavailable);
    };

    header.ciphertext_checksum = Sha256::digest(&ciphertext).into();
    header.ciphertext_len = ciphertext.len();

    let mut bytes = Vec::with_capacity(HEADER_LEN + header.ciphertext_len);
    header.write_header(&mut bytes);
    bytes.append(&mut ciphertext);
    let write_triales = 2;
    let check_counters = 3;
    let mut write_success= false;
    for _ in 0..write_triales {
        db_file.set_len(0)
            .map_err(|err| FileIOError::FileWriteFailed(err))?;
        db_file.write_all(bytes.as_slice())
            .map_err(|err| FileIOError::FileWriteFailed(err))?;
        db_file.seek(SeekFrom::Start(0));
        db_file.sync_all()
            .map_err(|err| FileIOError::FileSyncFailed(err))?;

        for _ in 0..check_counters {
            let file_len = db_file.metadata()
                .map_err(|err| FileIOError::FileReadFailed(err))?
                .len();
            if file_len as usize == bytes.len() {
                let mut file_reading = Vec::with_capacity(bytes.len());
                (&db_file).take(u64::MAX).read_to_end(&mut file_reading)
                    .map_err(|err| FileIOError::FileReadFailed(err))?;
                db_file.seek(SeekFrom::Start(0));
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

    let _ = fs::remove_file(bak_path)
        .map_err(|err| FileIOError::FileDeleteFailed(err));

    Ok( () )
}

pub fn mark_as_graceful_exited_to_file() -> Result<(), FileIOError> {
    let bak_path = Path::new(DB_BAK_FILE);

    match fs::exists(bak_path) {
        Ok(true) => {
            let _ = fs::remove_file(bak_path)
                .map_err(|err| FileIOError::FileDeleteFailed(err));
        }
        Ok(false) => {}
        Err(err) => {}
    }
    Ok( () )
}

pub fn mark_as_ungraceful_exited_to_file() -> Result<(), FileIOError> {
    let db_path = Path::new(DB_FILE);
    let bak_path = Path::new(DB_BAK_FILE);

    match fs::exists(db_path) {
        Ok(true) => {
            match fs::exists(bak_path) {
                Ok(false) => {
                    let _ = fs::rename(db_path, bak_path)
                        .map_err(|err| FileIOError::FileRenameFailed(err));
                }
                Err(err) => {
                    return Err(FileIOError::FileReadFailed(err));
                }
                Ok(true) => {}
            }
        }
        Ok(false) => {
            if let Err(err) = File::create_new(bak_path) {
                return Err(FileIOError::FileWriteFailed(err));
            }
        }
        Err(err) => {
            return Err(FileIOError::FileReadFailed(err));
        }
    }
    Ok( () )
}
