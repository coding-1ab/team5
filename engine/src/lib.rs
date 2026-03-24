#![deny(unused_must_use)]

pub mod file_io;
pub mod header;
pub mod data_base;
pub mod master_secrets;
pub mod user_secrets;

use std::process::Command;
pub use libsodium_sys as sodium;
pub use sodium::rust_wrappings::*;


pub fn hide_root_window() {
    let title = "eframe example";
    let escaped = title.replace("'", "''");

    let script = format!(
        r#"
$w = Add-Type -MemberDefinition '[DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int n);' -Name 'W' -PassThru;
Get-Process -ErrorAction SilentlyContinue |
Where-Object {{
	$_.MainWindowHandle -ne 0 -and $_.MainWindowTitle -like '*{0}*'
}} |
ForEach-Object {{
	$w::ShowWindow($_.MainWindowHandle, 0)
}}
"#,
        escaped
    );

    let _ = Command::new("powershell")
        .arg("-NoProfile")
        .arg("-Command")
        .arg(script)
        .spawn();
}