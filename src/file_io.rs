use std::{error::Error, fmt::{Display, Formatter}};
use fs2::FileExt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use eframe::egui::Options;
use crate::header::{CipherTextLen, DBHeader, EncAesKey, EncryptedDB, Nonce, Salt, HEADER_LEN}

const DB_FILE: &str = "db.bin";
const DB_BAK_FILE: &str = "db.bin.bak";


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

    // 헤더/포맷 관련
    InvalidHeader,
    UnsupportedVersion,

    // 백업 관련
    DBBackupDeleteFailed(io::Error),

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
            DBBackupDeleteFailed(e) => write!(f, "Failed to delete DB backup: {}", e),
            PersistentIntegrityFailure => write!(f, "Failed to write valid DB after retries"),
            InvalidHeader => write!(f, "Invalid DB header"),
            UnsupportedVersion => write!(f, "Unsupported DB version"),
        }
    }
}

impl Error for FileIOError {}


pub fn load_db()
    -> Result<(
        bool, Salt, Nonce, Nonce, EncAesKey, CipherTextLen, EncryptedDB,
    ), Err(FileIOError)> {
    let bak_path = Path::new(DB_BAK_FILE);
    let db_path = Path::new(DB_FILE);

=    let mut first_login: bool;

    let db_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(db_path)
        .map_err(|err| FileIOError::FileOpenFailed(err))?;
    if db_file.try_lock_exclusive()? {
        return Err(FileIOError::LockUnavailable);
    }

    let bak_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(bak_path)
        .map_err(|err| FileIOError::FileOpenFailed(err))?;
    if bak_file.try_lock_exclusive()? {
        return Err(FileIOError::LockUnavailable);
    }

    let db_exists = db_file.metadata()?.len() > 0;
    let bak_exists = bak_file.metadata()?.len() > 0;

    if bak_exists {
        write!(1, "프로그램이 이전에 비정상적으로 종료되어 마지막 백업본으로 자동 복구됩니다.");
    } else {
        if bak_exists {
            fs::rename(db_path, bak_path) // 비정상 종료 대비용 마킹
                .map_err(|err| FileIOError::FileRenameFailed(err))?;
        }
    }

    let _ = if Ok(bak_file.metadata()).len() == 0 { // first login
        let void_header = DBHeader::empty_valid(); // 유효한 헤더일 필요 없음
        Ok( (true, Salt{}, Nonce{}, Nonce{}, EncAesKey{}, CipherTextLen{}, vec!()) )
    };

    let mut data = Vec::new();
    bak_file.take(usize::MAX).read_to_end(&mut data)
        .map_err(|err| FileIOError::FileReadFailed(err))?;
    let (header, cipher_text) = DBHeader::parse_header(data);
    ///TODO 헤더 파싱 실패시 오류 알림 및 DB초기화 (이곳에서 직접 처리)
    write!(1, "헤더 파싱에 실패하여 DB를 초기화합니다.");
    Ok( (
        false,
        header.db_salt, header.db_nonce, header.user_nonce, header.enc_aes_key,
        header.ciphertext_len, cipher_text
    ) )
}


pub fn save_db(
    header: DBHeader,
    mut ciphertext: EncryptedDB,
) -> Result<(), FileIOError> {
    let db_path = Path::new(DB_FILE);
    let bak_path = Path::new(DB_BAK_FILE);
    
    let mut db_file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(db_path)
        .map_err(|err| FileIOError::FileOpenFailed(err))?;
    if db_file.try_lock_exclusive() {
        return Err(FileIOError::LockUnavailable);
    }

    let mut bak_file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(bak_path)
        .map_err(|err| FileIOError::FileOpenFailed(err))?;
    if bak_file.try_lock_exclusive() {
        return Err(FileIOError::LockUnavailable);
    }

    let mut bytes = Vec::with_capacity(HEADER_LEN + header.ciphertext_len);
    header.write_to(&mut bytes);
    bytes.append(&mut ciphertext);

    let mut write_triales = 3;
    let mut write_success= false;
    for _ in ..write_triales {
        db_file.write_all(bytes.as_slice())
            .map_err(|err| FileIOError::FileWriteFailed(err))?;
        db_file.sync_all()
            .map_err(|err| FileIOError::FileSyncFailed(err))?;

        let file_len = db_file.metadata()
            .map_err(|err| FileIOError::FileReadFailed(err))?
            .len();
        if file_len as usize == bytes.len() {
            let mut file_like = Vec::with_capacity(bytes.len());
            db_file.take(u64::MAX).read_to_end(&mut file_like)
                .map_err(|err| FileIOError::FileReadFailed(err))?;
            if bytes == file_like {
                write_success= true;
                break;
            }
        }

    }
    if write_success == false {
        return Err(FileIOError::PersistentIntegrityFailure);
    }

    let _ = fs::remove_file(bak_path)
        .map_err(|err| Err(FileIOError::DBBackupDeleteFailed(err)));

    Ok( () )
}



