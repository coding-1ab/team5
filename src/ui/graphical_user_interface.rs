// todo
// 사이트 이름 + 계정 정보 주면 저장
// 사이트 이름 주면 계정 정보 불러오기
// 사이트 이름 주면 계정 정복 삭제하기

// 흠 뭐부터 하지

use eframe::egui::Context;
use eframe::{
    egui::{self, FontData},
    epaint::text::{FontInsert, FontPriority, InsertFontFamily},
};
use std::{collections::HashMap, fs, io};
use crate::data_base::{prefix_range, DB};

type TryCountRamming = i64;
type FontLoadState = (TryCountRamming, bool);
type FontLoadList = HashMap<&'static str, FontLoadState>;

const CAN_TRY_LOAD_COUNT: i64 = 5;

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
    font_load_list: FontLoadList,
    login: bool,
    id: String,
    password: String,
    re_check_password: String,
    data_base: Option<DB>,
    search_data_base: String,
    window_open_list: WindowOpenList,
    output: String,
}

impl GraphicalUserInterface {
    pub fn setting_database(&mut self, data_base: DB) {
        self.data_base = Some(data_base);
    }

    fn font_load(&mut self, context: &Context, name: &'static str, font_data: FontData, insert_font_family: InsertFontFamily, ) -> Result<(), io::Error> {
        let (font_try_count_ramming, is_font_load) = self.font_load_list.entry(name).or_default();
        font_load(context, name, font_data, insert_font_family, is_font_load, font_try_count_ramming)
    }

    fn font_load_malgun_gothic_font(&mut self, context: &Context) {
        let font_file_contents = match fs::read(r"C:\Windows\Fonts\malgun.ttf") {
            Ok(contents) => contents,
            Err(e) => {
                eprintln!("Error loading malgun gothic: {:?}", e);
                return;
            }
        };
        let font_data = FontData::from_owned(font_file_contents);

        match self.font_load(
            context, "malgun_gothic", font_data,
            InsertFontFamily {
                family: egui::FontFamily::Proportional,
                priority: FontPriority::Highest,
            },
        ) {
            Ok(_) => println!("Successfully loaded malgun gothic"),
            Err(e) => println!("Error loading malgun gothic: {:?}", e),
        };
    }

    fn font_load_nanum_gothic_font(&mut self, context: &Context) {
        let font_data = FontData::from_static(include_bytes!("../../NanumGothic.ttf"));

        match self.font_load(
            context, "nanum_gothic", font_data,
            InsertFontFamily {
                family: egui::FontFamily::Proportional,
                priority: FontPriority::Highest,
            },
        ) {
            Ok(_) => println!("Successfully loaded nanum gothic"),
            Err(e) => println!("Error loading nanum gothic: {:?}", e),
        }
    }

    fn font_load_emoji_font(&mut self, context: &Context) {
        let font_file_contents = match fs::read(r"C:\Windows\Fonts\seguiemj.ttf") {
            Ok(contents) => contents,
            Err(e) => {
                eprintln!("Error loading emoji_font: {:?}", e);
                return;
            }
        };
        let font_data = FontData::from_owned(font_file_contents);

        match self.font_load(
            context, "windows_emoji", font_data,
            InsertFontFamily {
                family: egui::FontFamily::Proportional,
                priority: FontPriority::Highest,
            },
        ) {
            Ok(_) => println!("Successfully loaded emoji_font"),
            Err(e) => println!("Error loading emoji_font: {:?}", e),
        }
    }
}

impl Default for GraphicalUserInterface {
    fn default() -> Self {
        Self {
            first_run: true,
            font_load_list: FontLoadList::default(),
            login: false,
            id: String::new(),
            password: String::new(),
            re_check_password: String::new(),
            search_data_base: String::new(),
            data_base: Default::default(),
            window_open_list: Default::default(),
            output: String::new(),
        }
    }
}

impl eframe::App for GraphicalUserInterface {
    fn update(&mut self, ctx: &Context, _frame: &mut eframe::Frame) {
        if self.first_run {
            self.font_load_malgun_gothic_font(ctx);
            self.font_load_nanum_gothic_font(ctx);
            self.font_load_emoji_font(ctx);
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
                        // todo
                        /*
                        egui::Grid::new("login_grid").num_columns(2).spacing([8.0, 6.0]).show(ui, |ui| {
                            ui.label("id");
                            ui.text_edit_singleline(&mut self.id);
                            ui.end_row();
                            ui.label("password");
                            ui.add(egui::TextEdit::singleline(&mut self.password).password(true));
                        });
                        */
                        egui::Grid::new("master_login_grid")
                            .num_columns(2)
                            .show(ui, |ui| {
                                ui.label("마스터 로그인");
                                // todo
                                // ui.text_edit_singleline()
                            });
                        ui.horizontal(|ui| {
                            ui.label("master password");
                            ui.add(egui::TextEdit::singleline(&mut self.password).password(true));
                        });
                        ui.horizontal(|ui| {
                            ui.label("master password");
                            ui.add(
                                egui::TextEdit::singleline(&mut self.re_check_password)
                                    .password(true),
                            );
                        });
                        let login_button = ui.button("로그인");
                        if login_button.hovered() {
                            ui.label("asdf");
                        }
                        if login_button.clicked() {
                            if self.password != self.re_check_password {
                                ui.label("invalid password");
                                return;
                            }
                            println!("login_click");

                            // todo
                            /*
                            let master_password_32 = match CryptoKey::new(&self.password) {
                                Ok(master_password_32) => master_password_32,
                                 Err(err) => {
                                    dbg!(err);
                                    return
                                }
                            };
                            println!("master password: {:?}", master_password_32);
                            */

                            self.window_open_list.set("master_login", false);
                            self.login = true;
                        }
                    });
                },
            );
        }

        if self.login {
            egui::CentralPanel::default().show(ctx, |ui| {
                ui.label("search");
                ui.add(egui::TextEdit::singleline(&mut self.search_data_base));
                egui::ScrollArea::vertical().show(ui, |ui| {
                    let Some(data_base) = &self.data_base else {
                        ui.label("invalided data base!");
                        return;
                    };
                    for user_data in prefix_range(data_base, &self.search_data_base) {
                        egui::Grid::new("user_data").show(ui, |ui| {
                            let (site_name, user_data) = user_data;
                            ui.label(&site_name.0);
                            if ui.button("asdf").clicked() {

                            }
                        });
                    }
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
                                egui::Grid::new("test_grid")
                                    .num_columns(2)
                                    .spacing([8.0, 6.0])
                                    .show(ui, |ui| {
                                        ui.label("id");
                                        ui.text_edit_singleline(&mut self.id);
                                        ui.end_row();
                                        ui.label("password");
                                        ui.add(
                                            egui::TextEdit::singleline(&mut self.password)
                                                .password(true),
                                        );
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
                    self.output = format!(
                        "You typed id: {}\nYou typed password: {}",
                        self.id, self.password
                    );
                }

                ui.separator();

                ui.label("Output:");
                ui.label(&self.output);
            });
        }
    }
}

fn add_font(context: &Context, name: &str, font_data: FontData, font_family: InsertFontFamily) {
    let font = FontInsert::new(name, font_data, vec![font_family]);
    context.add_font(font);
}

pub fn font_load(
    context: &Context,
    name: &str,
    font_data: FontData,
    insert_font_family: InsertFontFamily,
    is_font_load: &mut bool,
    try_load_count: &mut i64,
) -> Result<(), io::Error> {
    if !*is_font_load {
        *try_load_count += 1;
        add_font(context, name, font_data, insert_font_family);
        *is_font_load = true;
    }
    Ok(())
}

fn try_until<T, E>(mut to_try: impl FnMut() -> Result<T, E>) -> Result<T, E> {
    for i in 1..=CAN_TRY_LOAD_COUNT {
        match to_try() {
            Ok(v) => return Ok(v),
            Err(e) => {
                if i == CAN_TRY_LOAD_COUNT {
                    return Err(e);
                }
            }
        }
    };

    unreachable!()
}
