// todo
// 사이트 이름 + 계정 정보 주면 저장
// 사이트 이름 주면 계정 정보 불러오기
// 사이트 이름 주면 계정 정복 삭제하기

// 흠 뭐부터 하지

use std::{fs, io, sync::Arc, collections::HashMap};
use std::path::Path;
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
use eframe::egui::Context;
use crate::credential::{prefix_range, DB};
use crate::gen_key::CryptoKey;

type TryCountRamming = i64;
type FontLoadState = (TryCountRamming, bool);

const CAN_TRY_LOAD_COUNT: i64 = 5;

struct FontLoadList(HashMap<&'static str, FontLoadState>);


#[derive(Default)]
struct WindowOpenList(HashMap<&'static str, bool>);

impl WindowOpenList {
    fn new() -> Self {
        Self(HashMap::new())
    }

    fn get(&self, key: &str) -> bool {
        self.0.get(key).copied().unwrap_or(false)
    }

    fn set(&mut self, key: &'static str, value: bool) {
        self.0.insert(key, value);
    }
}

impl AsRef<HashMap<&'static str, bool>> for WindowOpenList {
    fn as_ref(&self) -> &HashMap<&'static str, bool> {
        &self.0
    }
}

pub struct GraphicalUserInterface {
    first_run: bool,
    load_malgun_gothic_font: bool,
    load_nanum_gothic_font: bool,
    try_load_count_malgun_gothic_font: i64,
    try_load_count_nanum_gothic_font: i64,
    login: bool,
    id: String,
    password: String,
    data_base: DB,
    window_open_list: WindowOpenList,
    output: String,
}

impl GraphicalUserInterface {
    pub fn setting_database(&mut self, data_base: DB) {
        self.data_base = data_base;
    }

    pub fn font_load<P: AsRef<Path>>(context: &Context, name: &str, file_path: P, insert_font_family: InsertFontFamily, is_font_load: &mut bool, try_load_count: &mut i64) -> Result<(), io::Error> {
        if !*is_font_load {
            *try_load_count += 1;
            let font_data = fs::read(file_path)?;
            add_font(context, name, FontData::from_owned(font_data), insert_font_family);
        }
        Ok(())
    }
}

impl Default for GraphicalUserInterface {
    fn default() -> Self {
        Self {
            first_run: true,
            load_malgun_gothic_font: false,
            load_nanum_gothic_font: false,
            try_load_count_malgun_gothic_font: 0,
            try_load_count_nanum_gothic_font: 0,
            login: false,
            id: String::new(),
            password: String::new(),
            data_base: Default::default(),
            window_open_list: Default::default(),
            output: String::new()
        }
    }
}

impl eframe::App for GraphicalUserInterface {
    fn update(&mut self, ctx: &Context, _frame: &mut eframe::Frame) {
        if self.first_run {
            match Self::font_load(
                ctx, "malgun_gothic", r"C:\Windows\Fonts\malgun.ttf", InsertFontFamily { family: egui::FontFamily::Proportional, priority: FontPriority::Highest },
                &mut self.load_malgun_gothic_font, &mut self.try_load_count_malgun_gothic_font
            ) {
                Ok(_) => {
                    println!("Successfully loaded malgun gothic");
                    self.load_malgun_gothic_font = true;
                }
                Err(e) => {
                    println!("Error loading malgun gothic: {:?}", e);
                    self.load_malgun_gothic_font = false;
                }
            }
            match Self::font_load(
                ctx, "nanum_gothic", r"/NanumGothic.ttf", InsertFontFamily { family: egui::FontFamily::Proportional, priority: FontPriority::Highest },
                &mut self.load_nanum_gothic_font, &mut self.try_load_count_nanum_gothic_font
            ) {
                Ok(_) => {
                    println!("Successfully loaded nanum gothic");
                    self.load_nanum_gothic_font = true;
                }
                Err(e) => {
                    println!("Error loading nanum gothic: {:?}", e);
                    self.load_nanum_gothic_font = false;
                }
            }
            self.window_open_list.set("master_login", true);
            self.first_run = false;
        }

        let master_login_viewport_id = egui::ViewportId::from_hash_of("master_login");

        if self.window_open_list.get("master_login") {
            ctx.show_viewport_immediate(
                egui::ViewportId::from_hash_of("master_login"),
                egui::ViewportBuilder::default().with_title("마스터 로그인"),
                |ctx, _| {
                    if ctx.input(|i| i.viewport().close_requested()) {
                        self.window_open_list.set("master_login", false);
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                    egui::CentralPanel::default().show(ctx, |ui| {
                        /*
                        egui::Grid::new("login_grid").num_columns(2).spacing([8.0, 6.0]).show(ui, |ui| {
                            ui.label("id");
                            ui.text_edit_singleline(&mut self.id);
                            ui.end_row();
                            ui.label("password");
                            ui.add(egui::TextEdit::singleline(&mut self.password).password(true));
                        });
                        */
                        egui::Grid::new("master_login_grid").num_columns(2).show(ui, |ui| {
                            ui.label("마스터 로그인");
                            // ui.text_edit_singleline()
                        });
                        ui.horizontal(|ui| {
                            ui.label("master password");
                            ui.add(egui::TextEdit::singleline(&mut self.password).password(true));
                        });
                        ui.horizontal(|ui| {
                            ui.label("master password");
                            ui.add(egui::TextEdit::singleline(&mut self.password).password(true));
                        });
                        let login_button = ui.button("로그인");
                        if login_button.hovered() {
                            ui.label("asdf");
                        }
                        if login_button.clicked() {
                            println!("login_click");

                            let master_password_32 = match CryptoKey::new(&self.password) {
                                Ok(master_password_32) => master_password_32,
                                 Err(err) => {
                                    dbg!(err);
                                    return
                                }
                            };
                            println!("master password: {:?}", master_password_32);

                            self.window_open_list.set("master_login", false);
                            self.login = true;
                        }
                    });
                },
            );
        }

        if self.login {
            egui::CentralPanel::default().show(ctx, |ui| {
                egui::ScrollArea::vertical().show(ui, |ui| {
                    prefix_range(&self.data_base, )
                });

                if ui.button("Submit").clicked() {
                    self.window_open_list.set("test", true);
                    ctx.show_viewport_immediate(
                        egui::ViewportId::from_hash_of("test"),
                        egui::ViewportBuilder::default().with_title("ad asdf"),
                        |ctx, _| {
                            if ctx.input(|i| i.viewport().close_requested()) {
                                println!("닫기!");
                                self.window_open_list.set("test", false);
                                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                            }
                            egui::CentralPanel::default().show(ctx, |ui| {
                                egui::Grid::new("test_grid").num_columns(2).spacing([8.0, 6.0]).show(ui, |ui| {
                                    ui.label("id");
                                    ui.text_edit_singleline(&mut self.id);
                                    ui.end_row();
                                    ui.label("password");
                                    ui.add(egui::TextEdit::singleline(&mut self.password).password(true));
                                });
                                let login_button = ui.button("asdf");
                                if login_button.hovered() {
                                    ui.label("asdf");
                                }
                                if login_button.clicked() {
                                    self.window_open_list.set("test", false);
                                    self.login = true;
                                }
                            });
                        },
                    );
                    self.output = format!("You typed id: {}\nYou typed password: {}", self.id, self.password);
                }

                ui.separator();

                ui.label("Output:");
                ui.label(&self.output);
            });
        }
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

fn add_font(context: &egui::Context, name: &str, font_data: FontData, font_family: InsertFontFamily) {
    let font = FontInsert::new(name, font_data, vec![font_family]);
    context.add_font(font);
}

fn add_malgun_gothic_font(context: &egui::Context, font_family: InsertFontFamily) -> Result<(), io::Error> {
    let font_data = fs::read(r"C:\Windows\Fonts\malgun.ttf")?;
    Ok(add_font(context, "malgun_gothic", FontData::from_owned(font_data), font_family))
}