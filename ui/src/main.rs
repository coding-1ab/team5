#![deny(unused_mut)]
#![deny(unused_crate_dependencies)]
//#![deny(deprecated)]
#![deny(clippy::cognitive_complexity)]
#![deny(clippy::complexity)]
#![deny(clippy::too_many_lines)]
#![warn(unused)]

use std::ffi::c_void;
use eframe::{
    CreationContext,
    egui,
    egui::FontData,
    epaint::text::{FontInsert, FontPriority, InsertFontFamily},
    egui::ViewportBuilder
};
use eframe::egui::ViewportCommand;
use eframe::wgpu::rwh::{HasRawWindowHandle, HasWindowHandle, RawWindowHandle};
use single_instance::SingleInstance;
use libsodium_sys::rust_wrappings::init::sodium_init;
use graphical_user_interface::GraphicalUserInterface;

mod command_builder;
mod graphical_user_interface;
mod window;

fn main() {
    sodium_init().expect("이거 깨지면 답없음");
    let instance = SingleInstance::new("team5").unwrap();
    if !instance.is_single() {
        return;
    }

    let options = eframe::NativeOptions {
        centered: true,
        viewport: ViewportBuilder::default().with_visible(false).with_resizable(false),
        ..eframe::NativeOptions::default()
    };
    let result = eframe::run_native(
        "eframe example",
        options,
        Box::new(|cc| {
            let mut graphical_user_interface = GraphicalUserInterface::default();
            #[cfg(target_os = "windows")]
            {
                let center = get_monitor_center(get_hwnd(cc.raw_window_handle().unwrap()).unwrap()).unwrap();
                graphical_user_interface.center = center.into();
            }
            cc.egui_ctx.send_viewport_cmd(ViewportCommand::Visible(false));
            //cc.egui_ctx.send_viewport_cmd(ViewportCommand::Visible(false)); // 있으니까 입력이 안되는데?
            init_fonts(cc);
            Ok(Box::new(graphical_user_interface))
        })
    );
    dbg!(result);
}

fn init_fonts(cc: &CreationContext) {
    let nanum_gothic_font_data = FontData::from_static(include_bytes!("../NanumGothic.ttf"));
    let nanum_gothic_insert_font_family = InsertFontFamily {
        family: egui::FontFamily::Proportional,
        priority: FontPriority::Lowest,
    };
    let nanum_gothic_font = FontInsert::new(
        "nanum_gothic",
        nanum_gothic_font_data,
        vec![nanum_gothic_insert_font_family],
    );
    cc.egui_ctx.add_font(nanum_gothic_font);
}

#[cfg(target_os = "windows")]
use windows::Win32::{
    Foundation::{HWND, RECT},
    UI::WindowsAndMessaging::{GetWindowRect},
    Graphics::Gdi::{
        MonitorFromWindow, GetMonitorInfoW, MONITORINFO, MONITOR_DEFAULTTONEAREST,
    },
};

#[cfg(target_os = "windows")]
fn get_hwnd(raw: RawWindowHandle) -> Option<HWND> {
    match raw {
        RawWindowHandle::Win32(handle) => {
            Some(HWND(handle.hwnd.get() as *mut c_void))
        }
        _ => None,
    }
}

#[cfg(target_os = "windows")]
fn get_monitor_center(hwnd: HWND) -> Option<(i32, i32)> {
    unsafe {
        let hmonitor = MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST);

        let mut mi = MONITORINFO {
            cbSize: std::mem::size_of::<MONITORINFO>() as u32,
            ..Default::default()
        };

        if GetMonitorInfoW(hmonitor, &mut mi).as_bool() {
            let rect = mi.rcMonitor;

            let center_x = (rect.left + rect.right) / 2;
            let center_y = (rect.top + rect.bottom) / 2;

            Some((center_x, center_y))
        } else {
            None
        }
    }
}