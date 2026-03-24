#![windows_subsystem = "windows"]

use eframe::egui::ViewportCommand;
use single_instance::SingleInstance;
use engine::hide_root_window;

fn main() {
    let instance = SingleInstance::new("team5").unwrap();
    if !instance.is_single() {
        return;
    }

    #[cfg(feature = "gui")]
    {
        use std::fs;
        use eframe::{
            egui,
            egui::FontData,
            epaint::text::{FontPriority, InsertFontFamily, FontInsert}
        };
        use ui::graphical_user_interface::GraphicalUserInterface;
        let options = eframe::NativeOptions::default();
        eframe::run_native(
            "eframe example",
            options,
            Box::new(|cc| {
                cc.egui_ctx.send_viewport_cmd(ViewportCommand::Visible(false)); // 있으니까 입력이 안되는데?
                let insert_font_family = InsertFontFamily {
                    family: egui::FontFamily::Proportional,
                    priority: FontPriority::Highest,
                };
                let malgun_gothic_font_file_contents = fs::read(r"C:\Windows\Fonts\malgun.ttf").unwrap_or_else(|error| {
                    eprintln!("Error loading malgun gothic {}", error);
                    Vec::new()
                });
                let malgun_gothic_font_data = FontData::from_owned(malgun_gothic_font_file_contents);
                let malgun_gothic_font = FontInsert::new("malgun_gothic", malgun_gothic_font_data, vec![insert_font_family.clone()]);
                cc.egui_ctx.add_font(malgun_gothic_font);
                let nanum_gothic_font_data = FontData::from_static(include_bytes!("../NanumGothic.ttf"));
                let nanum_gothic_font = FontInsert::new("nanum_gothic", nanum_gothic_font_data, vec![insert_font_family.clone()]);
                cc.egui_ctx.add_font(nanum_gothic_font);
                let emoji_font_file_contents = fs::read(r"C:\Windows\Fonts\seguiemj.ttf").unwrap_or_else(|error| {
                    eprintln!("Error loading emoji_font: {:?}", error);
                    Vec::new()
                });
                let emoji_font_data = FontData::from_owned(emoji_font_file_contents);
                let emoji_font = FontInsert::new("windows_emoji", emoji_font_data, vec![insert_font_family]);
                cc.egui_ctx.add_font(emoji_font);
                Ok(Box::new(GraphicalUserInterface::default()))
            }),
        ).unwrap();
    }
}