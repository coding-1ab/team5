use eframe::egui::{FontData, ViewportCommand};
use eframe::epaint::text::FontInsert;
use single_instance::SingleInstance;

fn main() {
    let instance = SingleInstance::new("team5").unwrap();
    if !instance.is_single() {
        return;
    }

    #[cfg(feature = "gui")]
    {
        use ui::graphical_user_interface::GraphicalUserInterface;
        let options = eframe::NativeOptions::default();
        eframe::run_native(
            "eframe example",
            options,
            Box::new(|cc| {
                cc.egui_ctx.send_viewport_cmd(ViewportCommand::Visible(false)); // 있으니까 입력이 안되는데?
                let nanum_gothic_font_data = FontData::from_static(include_bytes!("../NanumGothic.ttf"));
                let nanum_gothic_font = FontInsert::new("nanum_gothic", nanum_gothic_font_data, Vec::new());
                cc.egui_ctx.add_font(nanum_gothic_font);
                Ok(Box::new(GraphicalUserInterface::default()))
            }),
        ).unwrap()
    }
}