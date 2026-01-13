// todo
// 사이트 이름 + 계정 정보 주면 저장
// 사이트 이름 주면 계정 정보 불러오기
// 사이트 이름 주면 계정 정복 삭제하기

// 흠 뭐부터 하지

use std::{fs, io, sync::Arc};
use eframe::{
    egui::{
        self,
        FontData
    },
    epaint::{
        self,
        text::{InsertFontFamily, FontPriority, FontInsert}
    }
};
use team5::{secrets::Secrets, Credential};

const CAN_TRY_LOAD_COUNT: i64 = 5;

#[derive(Default)]
pub struct GraphicalUserInterface {
    load_malgun_gothic_font: bool,
    try_load_count_malgun_gothic_font: i64,
    secrets: Secrets,
    id: String,
    password: String,
    output: String,
    window: bool
}

impl eframe::App for GraphicalUserInterface {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if !self.load_malgun_gothic_font && self.try_load_count_malgun_gothic_font < CAN_TRY_LOAD_COUNT {
            println!("맑은 고딕 폰트 로드 시도");
            self.try_load_count_malgun_gothic_font += 1;
            match add_malgun_gothic_font(ctx, InsertFontFamily { family: egui::FontFamily::Proportional, priority: FontPriority::Highest }) {
                Ok(_) => {
                    println!("맑은 고딕 폰트 로드 성공");
                    self.load_malgun_gothic_font = true;
                },
                Err(error) => {
                    println!("맑은 고딕 폰트 로드 실패: {}", error);
                    self.load_malgun_gothic_font = false;
                }
            };
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            egui::Grid::new("login_grid").num_columns(2).spacing([8.0, 6.0]).show(ui, |ui| {
                ui.label("id");
                ui.text_edit_singleline(&mut self.id);
                ui.end_row();
                ui.label("password");
                ui.text_edit_singleline(&mut self.password);
            });

            ui.heading("eframe example");

            if self.window {
                ctx.show_viewport_immediate(
                    egui::ViewportId::from_hash_of("second"),
                    egui::ViewportBuilder::default().with_title("서브 창"),
                    |ctx, _| {
                        egui::CentralPanel::default().show(ctx, |ui| {
                            if ui.button("닫기").clicked() {
                                self.window = false;
                            }
                        });
                    },
                );
            }


            if ui.button("Submit").clicked() {
                self.window = true;
                self.output = format!("You typed id: {}\nYou typed password: {}", self.id, self.password);
            }

            ui.separator();

            ui.label("Output:");
            ui.label(&self.output);
        });
    }
}


impl GraphicalUserInterface {
    fn load_emoji_font(&mut self, ctx: &egui::Context) -> Result<(), io::Error> {
        let emoji = fs::read(r"C:\Windows\Fonts\seguiemj.ttf")?;

        let mut fonts = egui::FontDefinitions::default();

        fonts.font_data.insert(
            "windows_emoji".to_owned(),
            Arc::new(egui::FontData::from_owned(emoji)),
        );

        fonts.families.get_mut(&egui::FontFamily::Proportional).ok_or(io::Error::new(io::ErrorKind::InvalidData, "FontFamily is invalid!"))?
            .insert(0, "windows_emoji".to_string());

        ctx.set_fonts(fonts);

        Ok(())
    }
}

struct CharacterUserInterface {
    secrets: Secrets
}

impl CharacterUserInterface {

}

struct UserInterface {
    #[cfg(feature = "GraphicalUserInterface")]
    graphical_user_interface: GraphicalUserInterface,
    #[cfg(feature = "CharacterUserInterface")]
    character_user_interface: CharacterUserInterface
}

fn add_font(context: &egui::Context, name: &str, font_data: FontData, font_family: InsertFontFamily) {
    let font = FontInsert::new(name, font_data, vec![font_family]);
    context.add_font(font);
}

fn add_malgun_gothic_font(context: &egui::Context, font_family: InsertFontFamily) -> Result<(), io::Error> {
    let font_data = fs::read(r"C:\Windows\Fonts\malgun.ttf")?;
    Ok(add_font(context, "malgun_gothic", FontData::from_owned(font_data), font_family))
}
