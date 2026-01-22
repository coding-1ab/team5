use zeroize::Zeroizing;

pub mod file_io;
pub mod header;
pub mod crypto;
pub mod data_base;
pub mod master_secrets;
pub mod user_secrets;
pub mod ui;
// pub mod secrets;

pub type ZeroizingString = Zeroizing<String>; // DB 내부 이외 모든 문자열 데이터에 사용
