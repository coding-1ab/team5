
mod errors;
mod linux;
mod utils;
mod windows;
mod macos;

use errors::HWIDError;
#[cfg(target_os = "linux")]
pub use linux::*;
#[cfg(target_os = "windows")]
pub use windows::{get_disk_id, get_hwid, get_mac_address};
#[cfg(target_os = "macos")]
pub use macos::{get_disk_id, get_hwid, get_mac_address};
