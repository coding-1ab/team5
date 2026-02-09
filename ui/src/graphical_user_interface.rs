// todo
// 사이트 이름 + 계정 정보 주면 저장
// 사이트 이름 주면 계정 정보 불러오기
// 사이트 이름 주면 계정 정복 삭제하기

// 흠 뭐부터 하지

use eframe::{
    egui::{Context, ViewportCommand, self, FontData},
    epaint::text::{FontInsert, FontPriority, InsertFontFamily}
};
use std::{collections::HashMap, fs, io, error::Error, num::NonZeroU64};
use std::io::Read;
use eframe::egui::TextBuffer;
use zeroize::{Zeroize, Zeroizing};
use engine::{
    data_base::{prefix_range},
    file_io::{load_db, FileIOWarn},
    header::{DBHeader, EncryptedDB}
};
use engine::data_base::DB;
use engine::master_secrets::{decrypt_db, master_pw_validation, first_login, PubKey, SecKey, general_login};
use engine::user_secrets::WrappedUserKey;

type TryCountRamming = i64;
type FontLoadState = (TryCountRamming, bool);
type FontLoadList = HashMap<&'static str, FontLoadState>;

const CAN_TRY_LOAD_COUNT: NonZeroU64 = NonZeroU64::new(5).unwrap();

#[derive(Default)]
struct WindowOpenList(HashMap<&'static str, bool>);

impl WindowOpenList {
    fn get<'a>(&'a self, key: &str, default: &'a bool) -> &'a bool {
        self.0.get(key).unwrap_or(default)
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
    recheck_password: String,
    search_data_base: String,
    window_open_list: WindowOpenList,
    output: String,
    error_message: String,
    data_base: Option<DB>,
    data_base_header: Option<DBHeader>,
    public_key: Option<PubKey>,
    secret_key: Option<SecKey>,
    wrapped_user_key: Option<WrappedUserKey>
}

impl GraphicalUserInterface {
    fn font_load(&mut self, context: &Context, name: &'static str, font_data: FontData, insert_font_family: InsertFontFamily) -> Result<(), io::Error> {
        let (font_try_count_ramming, is_font_load) = self.font_load_list.entry(name).or_default();
        font_load(context, name, font_data, insert_font_family, is_font_load, font_try_count_ramming)
    }

    fn font_load_malgun_gothic_font(&mut self, context: &Context) -> Result<(), io::Error> {
        let font_file_contents = match fs::read(r"C:\Windows\Fonts\malgun.ttf") {
            Ok(contents) => contents,
            Err(error) => {
                return Err(error);
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
            Ok(_) => Ok(()),
            Err(error) => Err(error),
        }
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
            login: Default::default(),
            font_load_list: FontLoadList::default(),
            id: String::new(),
            password: String::new(),
            recheck_password: String::new(),
            search_data_base: String::new(),
            window_open_list: Default::default(),
            output: String::new(),
            error_message: String::new(),
            data_base: None,
            data_base_header: None,
            public_key: None,
            secret_key: None,
            wrapped_user_key: None,
        }
    }
}

impl eframe::App for GraphicalUserInterface {
    fn update(&mut self, ctx: &Context, _frame: &mut eframe::Frame) {
        if !*self.window_open_list.get("root", &true) {
            ctx.send_viewport_cmd(ViewportCommand::Close);
        }

        if self.first_run {
            match try_until(|| self.font_load_malgun_gothic_font(ctx), CAN_TRY_LOAD_COUNT) {
                Ok(_) => (),
                Err(error) => {
                    println!("Error loading malgun gothic");
                    println!("Error: {}", error);
                }
            };
            self.font_load_nanum_gothic_font(ctx);
            self.font_load_emoji_font(ctx);
            self.first_run = false;
        }

        if !self.login {
            match load_db() {
                Ok((mut user_warn, mut data_base_header, encrypted_data_base)) => {
                    if encrypted_data_base.is_none() {
                        self.window_open_list.set("first_master_login", true);
                    }
                    if encrypted_data_base.is_some() {
                        self.window_open_list.set("master_login", true);
                    }
                    if *self.window_open_list.get("first_master_login", &false) {
                        ctx.show_viewport_immediate(
                            egui::ViewportId::from_hash_of("first_master_login"),
                            egui::ViewportBuilder::default().with_title("first_master_login").with_always_on_top().with_inner_size([300.0, 150.0]),
                            |ctx, _| {
                                if ctx.input(|input_state| input_state.viewport().close_requested()) {
                                    self.window_open_list.set("root", false);
                                    return;
                                }
                                egui::CentralPanel::default().show(ctx, |ui| {
                                    ui.label("input new master password");
                                    ui.add(egui::TextEdit::singleline(&mut self.password).password(true));
                                    ui.label("recheck master password");
                                    ui.add(egui::TextEdit::singleline(&mut self.recheck_password).password(true));
                                    ui.label(format!("{}", self.error_message));
                                    if ui.button("Accept").clicked() {
                                        if let Err(err) = master_pw_validation(&self.password) {
                                            self.error_message = format!("Master password validation error: {}", err);
                                            self.password.zeroize();
                                            self.recheck_password.zeroize();
                                            return;
                                        }
                                        if self.password == self.recheck_password {
                                            let (public_key, data_base_header_salt, wrapped_user_key) = first_login(self.password.take());
                                            self.password.zeroize();
                                            self.recheck_password.zeroize();
                                            self.public_key = Some(public_key);
                                            data_base_header.db_salt = data_base_header_salt;
                                            self.wrapped_user_key = Some(wrapped_user_key);
                                            self.data_base = Some(DB::default());
                                            self.data_base_header = Some(data_base_header);
                                            self.window_open_list.set("login", true);
                                            self.login = true;
                                        } else {
                                            self.password.zeroize();
                                            self.recheck_password.zeroize();
                                            self.error_message = "password is mismatch".to_string();
                                            return;
                                        }
                                    }
                                });
                            }
                        )
                    }

                    /* todo
                    if let Some(encrypted_data_base) = encrypted_data_base {
                        self.data_base = Some(DataBase::new(is_fresh, user_warn, data_base_header))
                    }
                    */

                    if *self.window_open_list.get("master_login", &false) {
                        ctx.show_viewport_immediate(
                            egui::ViewportId::from_hash_of("master_login"),
                            egui::ViewportBuilder::default().with_title("마스터 로그인"),
                            |ctx, _| {
                                if ctx.input(|i| i.viewport().close_requested()) {
                                    self.window_open_list.set("root", false);
                                }
                                egui::CentralPanel::default().show(ctx, |ui| {
                                    ui.label("input master password");
                                    ui.add(egui::TextEdit::singleline(&mut self.password).password(true));
                                    ui.label("input recheck master password");
                                    ui.add(egui::TextEdit::singleline(&mut self.recheck_password).password(true));
                                    ui.label(format!("{}", self.error_message));
                                    if ui.button("login").clicked() {
                                        if self.password != self.recheck_password {
                                            self.error_message = "invalid password".to_string();
                                            return;
                                        }
                                        let (secret_key, public_key, wrapped_user_key) = match general_login(self.password.take(), self.data_base_header.unwrap().db_salt.clone()) {
                                            Ok(value) => {
                                                self.password.zeroize();
                                                self.recheck_password.zeroize();
                                                value
                                            },
                                            Err(error) => {
                                                self.error_message = format!("{}", error);
                                                self.password.zeroize();
                                                self.recheck_password.zeroize();
                                                return;
                                            }
                                        };
                                        let decrypted_data_base = match decrypt_db(&encrypted_data_base.unwrap(), secret_key) {
                                            Ok(decrypted_data_base) => decrypted_data_base,
                                            Err(error) => {
                                                self.error_message = format!("{}", error);
                                                return;
                                            }
                                        };
                                        self.data_base = Some(decrypted_data_base);
                                        self.data_base_header = Some(data_base_header);
                                        self.window_open_list.set("master_login", false);
                                        self.login = true;
                                    }
                                });
                            },
                        );
                    }
                },
                Err(err) => {
                    ctx.show_viewport_immediate(
                        egui::ViewportId::from_hash_of("master_login_err"),
                        egui::ViewportBuilder::default().with_title("error").with_always_on_top().with_inner_size([350.0, 25.0]),
                        |ctx, _| {
                            if ctx.input(|input_state| input_state.viewport().close_requested()) {
                                self.window_open_list.set("root", false);
                                return;
                            }
                            egui::CentralPanel::default().show(ctx, |ui| {
                                ui.label(format!("Error loading db: {}", err));
                            });
                        }
                    );
                    return;
                }
            };
        } else {
            egui::CentralPanel::default().show(ctx, |ui| {
                egui::Grid::new("user_input").show(ui, |ui| {
                    let add_password_button = ui.button("add password").on_hover_text("add password");
                    if add_password_button.clicked() {
                        self.window_open_list.set("add_password", true);
                    }
                    if *self.window_open_list.get("add_password", &false) {
                        ctx.show_viewport_immediate(
                            egui::ViewportId::from_hash_of("add_password"),
                            egui::ViewportBuilder::default().with_title("add password"),
                            |ctx, _| {
                                egui::CentralPanel::default().show(ctx, |ui| {
                                    let mut site_name = String::new();
                                    let mut user_id = String::new();
                                    let mut password = String::new();
                                    ui.label("add password");
                                    ui.horizontal(|ui| {
                                        ui.label("site name");
                                        ui.text_edit_singleline(&mut site_name);
                                    });
                                    ui.horizontal(|ui| {
                                        ui.label("user id");
                                        ui.text_edit_singleline(&mut user_id);
                                    });
                                    ui.horizontal(|ui| {
                                        ui.label("password");
                                        ui.text_edit_singleline(&mut password);
                                    });
                                    if ui.button("Accept").clicked() {
                                        if site_name.is_empty() || user_id.is_empty() || password.is_empty() {
                                            ui.label("empty input!");
                                        }

                                    }
                                })
                            }
                        );
                    }
                });
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
                            ui.label(&*site_name.as_str());
                            for (user_id, password) in user_data {
                                ui.label(user_id.as_str());
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
                                ctx.send_viewport_cmd(ViewportCommand::Close);
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

fn try_until<T, E>(mut to_try: impl FnMut() -> Result<T, E>, try_count: NonZeroU64) -> Result<T, E> {
    for i in 1..=try_count.get() {
        match to_try() {
            Ok(v) => return Ok(v),
            Err(e) => {
                if i == try_count.get() {
                    return Err(e);
                }
            }
        }
    };

    unreachable!()
}

fn retry_function<F, T, E>(mut try_function: F, try_count: NonZeroU64) -> Result<T, E>
where
    F: FnMut() -> Result<T, E>,
    T: Sized,
    E: Error,
{
    let mut last_err = None;

    for _ in 0..try_count.into() {
        match try_function() {
            Ok(v) => return Ok(v),
            Err(e) => last_err = Some(e),
        }
    }

    Err(last_err.expect("max_attempts > 0"))
}