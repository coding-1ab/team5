// todo
// 사이트 이름 + 계정 정보 주면 저장
// 사이트 이름 주면 계정 정보 불러오기
// 사이트 이름 주면 계정 정복 삭제하기

// 흠 뭐부터 하지

use eframe::{
    egui::{Context, ViewportCommand, self, FontData},
    epaint::text::{FontInsert, FontPriority, InsertFontFamily}
};
use std::{collections::HashMap, fs, io, num::NonZeroU64};
use std::cell::{Ref, RefCell, RefMut};
use std::collections::HashSet;
use std::ops::DerefMut;
use eframe::egui::{TextBuffer};
use zeroize::Zeroize;
use engine::{
    data_base::prefix_range,
    file_io::load_db,
    header::DBHeader
};
use engine::data_base::{add_user_pw, SiteName, UserID, UserPW, DB};
use engine::file_io::mark_as_ungraceful_exited_to_file;
use engine::master_secrets::{decrypt_db, master_pw_validation, first_login, PubKey, SecKey, general_login, EncryptedDB};
use engine::user_secrets::WrappedUserKey;

type TryCountRamming = i64;
type FontLoadState = (TryCountRamming, bool);
type FontLoadList = HashMap<&'static str, FontLoadState>;

const CAN_TRY_LOAD_COUNT: NonZeroU64 = NonZeroU64::new(5).unwrap();

macro_rules! string_values_default {
    () => {
        RefCell::new(String::new())
    }
}

struct WindowOpenList {
    root: bool,
    master_login: bool,
    login: bool,
    add_password: bool,
    change_password: bool,
}

impl Default for WindowOpenList {
    fn default() -> Self {
        Self {
            root: true,
            master_login: false,
            login: false,
            add_password: false,
            change_password: false,
        }
    }
}

#[derive(Default)]
struct StringValues {
    password: String,
    recheck_password: String,
    error_message: String,
    add_password_site_name: String,
    add_password_user_identifier: String,
    add_password_password: String,
    search_data_base: String
}

pub struct GraphicalUserInterface {
    first_run: bool,
    login: bool,
    font_load_list: FontLoadList,
    string_values: StringValues,
    window_open_list: WindowOpenList,
    data_base: DB,
    wrapped_user_key: WrappedUserKey,
    data_base_header: Option<DBHeader>,
    public_key: Option<PubKey>,
    secret_key: Option<SecKey>,
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

    fn graphical_user_interface_first_login(&mut self, context: &Context, encrypted_data_base: &EncryptedDB, data_base_header: DBHeader) {
        context.show_viewport_immediate(
            egui::ViewportId::from_hash_of("master_login"),
            egui::ViewportBuilder::default().with_title("마스터 로그인"),
            |ctx, _| {
                if ctx.input(|i| i.viewport().close_requested()) {
                    self.window_open_list.root = false;
                }
                egui::CentralPanel::default().show(ctx, |ui| {
                    ui.label("input master password");
                    ui.add(egui::TextEdit::singleline(&mut self.string_values.password).password(true));
                    ui.label("input recheck master password");
                    ui.add(egui::TextEdit::singleline(&mut self.string_values.recheck_password).password(true));
                    ui.label(&self.string_values.error_message);
                    if ui.button("login").clicked() {
                        if self.string_values.password != self.string_values.recheck_password {
                            self.string_values.error_message = "invalid password".to_string();
                            return;
                        }
                        let (secret_key, public_key, wrapped_user_key) = match general_login(self.string_values.password.take(), &self.data_base_header.unwrap().db_salt) {
                            Ok(value) => {
                                self.string_values.password.zeroize();
                                self.string_values.recheck_password.zeroize();
                                value
                            },
                            Err(error) => {
                                self.string_values.error_message = error.to_string();
                                self.string_values.password.zeroize();
                                self.string_values.recheck_password.zeroize();
                                return;
                            }
                        };
                        let decrypted_data_base = match decrypt_db(&encrypted_data_base, secret_key) {
                            Ok(decrypted_data_base) => decrypted_data_base,
                            Err(error) => { 
                                self.string_values.error_message = error.to_string();
                                return;
                            }
                        };
                        self.data_base = decrypted_data_base;
                        self.data_base_header = Some(data_base_header);
                        self.public_key = Some(public_key);
                        self.wrapped_user_key = wrapped_user_key;
                        self.window_open_list.master_login = false;
                        self.login = true;
                    }
                });
            },
        );
    }

    fn graphical_user_interface_not_first_login(&mut self, context: &Context, mut data_base_header: DBHeader) {
        context.show_viewport_immediate(
            egui::ViewportId::from_hash_of("first_master_login"),
            egui::ViewportBuilder::default().with_title("first_master_login").with_always_on_top().with_inner_size([300.0, 150.0]),
            |ctx, _| {
                if ctx.input(|input_state| input_state.viewport().close_requested()) {
                    self.window_open_list.root = false;
                    return;
                }
                egui::CentralPanel::default().show(ctx, |ui| {
                    ui.label("input new master password");
                    ui.add(egui::TextEdit::singleline(&mut self.string_values.password).password(true));
                    ui.label("recheck master password");
                    ui.add(egui::TextEdit::singleline(&mut self.string_values.recheck_password).password(true));
                    ui.label(&self.string_values.error_message);
                    if ui.button("Accept").clicked() {
                        if let Err(err) = master_pw_validation(&self.string_values.password) {
                            self.string_values.error_message = format!("Master password validation error: {}", err);
                            self.string_values.password.zeroize();
                            self.string_values.recheck_password.zeroize();
                            return;
                        }
                        if self.string_values.password == self.string_values.recheck_password {
                            let (public_key, data_base_header_salt, wrapped_user_key) = first_login(self.string_values.password.take());
                            self.string_values.password.zeroize();
                            self.string_values.recheck_password.zeroize();
                            self.public_key = Some(public_key);
                            data_base_header.db_salt = data_base_header_salt;
                            self.wrapped_user_key = wrapped_user_key;
                            self.data_base = DB::default();
                            self.data_base_header = Some(data_base_header);
                            self.window_open_list.login = true;
                            self.login = true;
                        } else {
                            self.string_values.password.zeroize();
                            self.string_values.recheck_password.zeroize();
                            self.string_values.error_message = "password is mismatch".to_string();
                            return;
                        }
                    }
                });
            }
        );
    }

    fn graphical_user_interface_add_user_password(&mut self, context: &Context, button: egui::Response) {
        if button.clicked() {
            self.window_open_list.add_password = true;
        }
        if self.window_open_list.add_password {
            context.show_viewport_immediate(
                egui::ViewportId::from_hash_of("add_password"),
                egui::ViewportBuilder::default().with_title("add password"),
                |ctx, _| {
                    if ctx.input(|input_state| input_state.viewport().close_requested()) {
                        self.window_open_list.add_password = false;
                    }
                    egui::CentralPanel::default().show(ctx, |ui| {
                        let site_name = &mut self.string_values.add_password_site_name;
                        let user_id = &mut self.string_values.add_password_user_identifier;
                        let password = &mut self.string_values.add_password_password;
                        ui.label("add password");
                        ui.horizontal(|ui| {
                            ui.label("site name");
                            ui.text_edit_singleline(site_name);
                        });
                        ui.horizontal(|ui| {
                            ui.label("user id");
                            ui.text_edit_singleline(user_id);
                        });
                        ui.horizontal(|ui| {
                            ui.label("password");
                            ui.text_edit_singleline(password);
                        });
                        ui.label(&self.string_values.error_message);
                        if ui.button("Accept").clicked() {
                            if site_name.is_empty() || user_id.is_empty() || password.is_empty() {
                                self.string_values.error_message = "empty input!".to_string()
                            }
                            let site_name = match SiteName::new(&site_name) {
                                Ok(site_name) => site_name,
                                Err(error) => {
                                    self.string_values.error_message = error.to_string();
                                    password.zeroize();
                                    return;
                                }
                            };
                            let user_id = match UserID::new(&user_id) {
                                Ok(user_id) => user_id,
                                Err(error) => {
                                    self.string_values.error_message = error.to_string();
                                    password.zeroize();
                                    return;
                                }
                            };
                            let password = match UserPW::new(&password) {
                                Ok(password) => password,
                                Err(error) => {
                                    self.string_values.error_message = error.to_string();
                                    password.zeroize();
                                    return;
                                }
                            };
                            if let Err(e) = add_user_pw(&mut self.data_base, site_name, user_id, password, &self.wrapped_user_key) {
                                println!("Error adding password: {}", e);
                            }
                            if let Err(err) = mark_as_ungraceful_exited_to_file() {
                                println!("Error saving status: {}", err);
                            }
                        }
                    })
                }
            );
        }
    }

    fn change_user_password(&mut self, context: &Context, button: egui::Response) {
        if button.clicked() {
            self.window_open_list.change_password = true;
        }
        if self.window_open_list.change_password {
            context.show_viewport_immediate(
                egui::ViewportId::from_hash_of("change_user_password"),
                egui::ViewportBuilder::default().with_title("change user password"),
                |ctx, _| {
                    egui::CentralPanel::default().show(ctx, |ui| {

                    });
                }
            );
        }
    }

    /*
    ChangeUserPW {site: SiteName, id: UserID, pw: UserPW},
    RemoveUserPW {site: SiteName, id: UserID},
    GetUserPW {site: SiteName, id: UserID},
    PrefixSearch {site: String},
    ChangeMasterPW,
    SaveDB,
    ExitAppWithSave,
    ExitAppWithoutSave,
    */
}

impl Default for GraphicalUserInterface {
    fn default() -> Self {
        Self {
            first_run: true,
            login: false,
            font_load_list: HashMap::new(),
            string_values: Default::default(),
            window_open_list: Default::default(),
            data_base: Default::default(),
            wrapped_user_key: Default::default(),
            data_base_header: None,
            public_key: None,
            secret_key: None,
        }
    }
}

impl eframe::App for GraphicalUserInterface {
    fn update(&mut self, ctx: &Context, _frame: &mut eframe::Frame) {
        if !self.window_open_list.root {
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
                Ok((user_warn, data_base_header, encrypted_data_base)) => {
                    if let Some(user_warn) = user_warn {
                        ctx.show_viewport_immediate(
                            egui::ViewportId::from_hash_of("user_warn"),
                            egui::ViewportBuilder::default().with_title("warn"),
                            |ctx, _| {
                                if ctx.input(|input| input.viewport().close_requested()) {
                                    ctx.send_viewport_cmd(ViewportCommand::Close);
                                }
                                egui::CentralPanel::default().show(ctx, |ui| {
                                    ui.label(format!("warn: {}", user_warn));
                                })
                            }
                        );
                    }
                    match encrypted_data_base {
                        Some(encrypted_data_base) => {
                            self.graphical_user_interface_first_login(ctx, &encrypted_data_base, data_base_header);
                        }
                        None => {
                            self.graphical_user_interface_not_first_login(ctx, data_base_header);
                        }
                    }
                },
                Err(err) => {
                    ctx.show_viewport_immediate(
                        egui::ViewportId::from_hash_of("master_login_err"),
                        egui::ViewportBuilder::default().with_title("error").with_always_on_top().with_inner_size([350.0, 25.0]),
                        |ctx, _| {
                            if ctx.input(|input_state| input_state.viewport().close_requested()) {
                                self.window_open_list.root = false;
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
                    let button = ui.button("add password").on_hover_text("add password");
                    self.graphical_user_interface_add_user_password(ctx, button);
                });
                ui.label("search");
                ui.add(egui::TextEdit::singleline(&mut self.string_values.search_data_base));
                egui::ScrollArea::vertical().show(ui, |ui| {
                    for user_data in prefix_range(&self.data_base, &self.string_values.search_data_base) {
                        egui::Grid::new("user_data").show(ui, |ui| {
                            let (site_name, user_data) = user_data;
                            ui.label(&*site_name.as_str());
                            for (user_id, password) in user_data {
                                ui.label(user_id.as_str());
                            }
                        });
                    }
                });
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
