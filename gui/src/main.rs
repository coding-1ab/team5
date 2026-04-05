#![deny(unused_mut)]
#![deny(clippy::cognitive_complexity)]
#![deny(clippy::complexity)]
#![deny(clippy::too_many_lines)]

use eframe::CreationContext;
use eframe::{
    egui,
    egui::FontData,
    epaint::text::{FontInsert, FontPriority, InsertFontFamily},
};
use single_instance::SingleInstance;

mod command_builder;
mod graphical_user_interface;
mod window;

use eframe::egui::{ViewportBuilder, ViewportCommand};
use graphical_user_interface::GraphicalUserInterface;

fn main() {
    let instance = SingleInstance::new("team5").unwrap();
    if !instance.is_single() {
        return;
    }

    let options = eframe::NativeOptions {
        centered: true,
        viewport: ViewportBuilder::default().with_visible(false),
        ..eframe::NativeOptions::default()
    };
    eframe::run_native(
        "eframe example",
        options,
        Box::new(|cc| {
            //cc.egui_ctx.send_viewport_cmd(ViewportCommand::Visible(false)); // 있으니까 입력이 안되는데?
            init_fonts(cc);
            Ok(Box::new(GraphicalUserInterface::default()))
        }),
    )
    .unwrap();
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
