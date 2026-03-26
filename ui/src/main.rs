#![windows_subsystem = "windows"]

use single_instance::SingleInstance;

fn main() {
    let instance = SingleInstance::new("team5").unwrap();
    if !instance.is_single() {
        return;
    }

    #[cfg(feature = "gui")]
    {

        use eframe::egui::{ViewportBuilder, ViewportCommand};
        use ui::graphical_user_interface::GraphicalUserInterface;
        let options = eframe::NativeOptions {
            centered: true,
            viewport: ViewportBuilder::default().with_visible(false),
            ..eframe::NativeOptions::default()
        };
        eframe::run_native(
            "eframe example",
            options,
            Box::new(|cc| {
                cc.egui_ctx.send_viewport_cmd(ViewportCommand::Visible(false)); // 있으니까 입력이 안되는데?
                init_fonts(cc);
                Ok(Box::new(GraphicalUserInterface::default()))
            }),
        ).unwrap();
    }
}

#[cfg(feature = "gui")]
use eframe::CreationContext;

#[cfg(feature = "gui")]
fn init_fonts(cc: &CreationContext) {
    use std::fs;
    use eframe::{
        egui,
        egui::FontData,
        epaint::text::{FontPriority, InsertFontFamily, FontInsert}
    };
    let malgun_gothic_font_file_contents = fs::read(r"C:\Windows\Fonts\malgun.ttf").unwrap_or_else(|error| {
        eprintln!("Error loading malgun gothic {}", error);
        Vec::new()
    });
    let malgun_gothic_insert_font_family = InsertFontFamily {
        family: egui::FontFamily::Proportional,
        priority: if malgun_gothic_font_file_contents.is_empty() { FontPriority::Lowest } else { FontPriority::Highest },
    };
    let malgun_gothic_font_data = FontData::from_owned(malgun_gothic_font_file_contents);
    let malgun_gothic_font = FontInsert::new("malgun_gothic", malgun_gothic_font_data, vec![malgun_gothic_insert_font_family]);
    cc.egui_ctx.add_font(malgun_gothic_font);
    let nanum_gothic_font_data = FontData::from_static(include_bytes!("../NanumGothic.ttf"));
    let nanum_gothic_insert_font_family = InsertFontFamily {
        family: egui::FontFamily::Proportional,
        priority: FontPriority::Lowest,
    };
    let nanum_gothic_font = FontInsert::new("nanum_gothic", nanum_gothic_font_data, vec![nanum_gothic_insert_font_family]);
    cc.egui_ctx.add_font(nanum_gothic_font);
    let emoji_font_file_contents = fs::read(r"C:\Windows\Fonts\seguiemj.ttf").unwrap_or_else(|error| {
        eprintln!("Error loading emoji_font: {:?}", error);
        Vec::new()
    });
    let emoji_font_data = FontData::from_owned(emoji_font_file_contents);
    let emoji_insert_font_family = InsertFontFamily {
        family: egui::FontFamily::Proportional,
        priority: FontPriority::Lowest,
    };
    let emoji_font = FontInsert::new("windows_emoji", emoji_font_data, vec![emoji_insert_font_family]);
    cc.egui_ctx.add_font(emoji_font);
}