// todo
// 사이트 이름 + 계정 정보 주면 저장
// 사이트 이름 주면 계정 정보 불러오기
// 사이트 이름 주면 계정 정복 삭제하기

// 흠 뭐부터 하지

use std::collections::{BTreeMap, HashMap, btree_map::Entry};
use std::error::Error;
use std::fmt::Display;
use eframe::{
    egui::TextBuffer,
    egui::{self, Context, ViewportCommand},
};
use eframe::egui::ViewportEvent;
use engine::file_io::{check_can_directly_exit, mark_as_graceful_exited_to_file, mark_as_ungraceful_exited_to_file, FileIOError, FileIOWarn};
use engine::user_secrets::UserKeyNonce;
use engine::{
    PubKey,
    data_base::{
        DB, SiteName, UserID, UserPW, add_user_pw, change_user_pw, prefix_range, remove_user_pw,
    },
    file_io::{load_db, save_db},
    header::DBHeader,
    master_secrets::{
        EncryptedDB, change_master_pw, decrypt_db, encrypt_db, first_login, general_login,
        master_pw_validation,
    },
    user_secrets::{WrappedUserKey, decrypt_user_pw},
};
use zeroize::Zeroize;
use crate::command_builder::{CommandValue, CommandBuilder};

#[derive(Debug)]
enum SaveError {
    FileIOError(FileIOError),
    NotingPublicKey,
    NothingDataBaseHeader
}

impl Display for SaveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl From<FileIOError> for SaveError {
    fn from(value: FileIOError) -> Self {
        SaveError::FileIOError(value)
    }
}

impl Error for SaveError {}

#[derive(Default)]
struct UserState {
    site_names: BTreeMap<SiteName, bool>,
    user_data: BTreeMap<SiteName, HashMap<UserID, bool>>,
}

#[allow(unused)]
impl UserState {
    fn update_site_name(&mut self, site_name: SiteName, value: bool) {
        self.site_names.insert(site_name, value);
    }

    fn get_site_name(&self, site_name: &SiteName) -> Option<&bool> {
        self.site_names.get(site_name)
    }

    fn get_mut_site_name(&mut self, site_name: &SiteName) -> Option<&mut bool> {
        self.site_names.get_mut(site_name)
    }

    fn entry_site_name(&mut self, site_name: SiteName) -> Entry<'_, SiteName, bool> {
        self.site_names.entry(site_name)
    }

    fn update_user_data(&mut self, site_name: SiteName, user_id: UserID, value: bool) {
        if let Some(data) = self.user_data.get_mut(&site_name) {
            if value {
                self.site_names.insert(site_name.clone(), true);
            }
            data.insert(user_id, value);
        }
    }

    fn get_user_data(&self, site_name: &SiteName, user_id: &UserID) -> Option<&bool> {
        self.user_data
            .get(site_name)
            .and_then(|data| data.get(user_id))
    }
}

struct WindowOpenList {
    root: bool,
    master_login: bool,
    login: bool,
    add_user_password: bool,
    change_user_password: bool,
    remove_user_password: bool,
    // get_user_password: bool,
    change_master_password: bool,
    add_user_password_with_site_name: BTreeMap<SiteName, bool>,
    change_user_password_with_site_name: BTreeMap<SiteName, bool>,
    remove_user_password_with_site_name: BTreeMap<SiteName, bool>,
    reset: bool,
    user_state: UserState,
}

impl Default for WindowOpenList {
    fn default() -> Self {
        Self {
            root: true,
            master_login: false,
            login: false,
            add_user_password: false,
            change_user_password: false,
            remove_user_password: false,
            // get_user_password: false,
            change_master_password: false,
            add_user_password_with_site_name: BTreeMap::new(),
            change_user_password_with_site_name: BTreeMap::new(),
            remove_user_password_with_site_name: BTreeMap::new(),
            reset: false,
            user_state: Default::default(),
        }
    }
}

#[derive(Default)]
struct MasterLogin {
    password: String,
    recheck_password: String,
    error_message: String,
    warning_message: String,
}

#[derive(Default)]
struct StringValues {
    search_data_base: String,
    save_data_base_label: String,
    save_error: String,
    master_login: MasterLogin,
    command_value: CommandValue,
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

#[derive(Default)]
pub struct GraphicalUserInterface {
    login: bool,
    string_values: StringValues,
    window_open_list: WindowOpenList,
    data_base: DB,
    wrapped_user_key: Option<WrappedUserKey>,
    user_key_nonce: Option<UserKeyNonce>,
    // get_user_password_user_password: Option<UserPW>,
    data_base_header: Option<DBHeader>,
    public_key: Option<PubKey>,
}

impl GraphicalUserInterface {
    fn existing_user(&mut self, context: &Context, encrypted_data_base: &EncryptedDB) {
        context.show_viewport_immediate(
            egui::ViewportId::from_hash_of("master_login"),
            egui::ViewportBuilder::default().with_title("마스터 로그인").with_inner_size([300.0, 150.0]),
            |ctx, _| {
                if ctx.input(|i| i.viewport().close_requested()) {
                    self.window_open_list.root = false;
                }
                egui::CentralPanel::default().show(ctx, |ui| {
                    ui.label("input master password");
                    ui.add(egui::TextEdit::singleline(&mut self.string_values.master_login.password).password(true));
                    ui.label("input recheck master password");
                    ui.add(egui::TextEdit::singleline(&mut self.string_values.master_login.recheck_password).password(true));
                    ui.label(&self.string_values.master_login.error_message);
                    if ui.button("login").clicked() {
                        if self.string_values.master_login.password != self.string_values.master_login.recheck_password {
                            self.string_values.master_login.error_message = "invalid password".to_string();
                            return;
                        }
                        let (secret_key, public_key, wrapped_user_key, user_key_nonce) =
                            general_login(&mut self.string_values.master_login.password.take(), &self.data_base_header.expect("unreachable").master_pw_salt);
                        self.string_values.master_login.password.zeroize();
                        self.string_values.master_login.recheck_password.zeroize();
                        let decrypted_data_base = match decrypt_db(&encrypted_data_base, secret_key) {
                            Ok(decrypted_data_base) => decrypted_data_base,
                            Err(error) => {
                                self.string_values.master_login.error_message = error.to_string();
                                return;
                            }
                        };
                        self.data_base = decrypted_data_base;
                        self.public_key = Some(public_key);
                        self.wrapped_user_key = Some(wrapped_user_key);
                        self.user_key_nonce = Some(user_key_nonce);
                        self.window_open_list.master_login = false;
                        self.login = true;
                    }
                    if ui.button("reset").clicked() {
                        self.window_open_list.reset = true;
                    }
                    if self.window_open_list.reset {
                        ctx.show_viewport_immediate(
                            egui::ViewportId::from_hash_of("reset"),
                            egui::ViewportBuilder::default().with_title("reset"),
                            |ctx, _| {
                                egui::CentralPanel::default().show(ctx, |ui| {
                                    ui.label("reset?");
                                    ui.horizontal(|ui| {
                                        if ui.button("submit").clicked() {
                                            *self = Self::default();
                                            self.window_open_list.reset = false;
                                        }
                                        if ui.button("cancel").clicked() {
                                            self.window_open_list.reset = false;
                                        }
                                    })
                                })
                            },
                        );
                    }
                    ui.label(&self.string_values.master_login.warning_message);
                });
            },
        );
    }

    fn first_login(&mut self, context: &Context, data_base_header: &mut DBHeader) {
        context.show_viewport_immediate(
            egui::ViewportId::from_hash_of("first_master_login"),
            egui::ViewportBuilder::default().with_title("첫 마스터 로그인").with_inner_size([300.0, 150.0]),
            |ctx, _| {
                if ctx.input(|input_state| input_state.viewport().close_requested()) {
                    self.window_open_list.root = false;
                    return;
                }
                egui::CentralPanel::default().show(ctx, |ui| {
                    ui.label("input new master password");
                    ui.add(egui::TextEdit::singleline(&mut self.string_values.master_login.password).password(true));
                    ui.label("recheck master password");
                    ui.add(egui::TextEdit::singleline(&mut self.string_values.master_login.recheck_password).password(true));
                    ui.label(&self.string_values.master_login.error_message);
                    if ui.button("Accept").clicked() {
                        if let Err(err) = master_pw_validation(&self.string_values.master_login.password) {
                            self.string_values.master_login.error_message = format!("Master password validation error: {}", err);
                            self.string_values.master_login.password.zeroize();
                            self.string_values.master_login.recheck_password.zeroize();
                            return;
                        }
                        if self.string_values.master_login.password == self.string_values.master_login.recheck_password {
                            let (public_key, data_base_header_salt, wrapped_user_key, user_key_nonce) = first_login(self.string_values.master_login.password.take());
                            self.string_values.master_login.password.zeroize();
                            self.string_values.master_login.recheck_password.zeroize();
                            data_base_header.master_pw_salt = data_base_header_salt;
                            self.data_base_header = Some(*data_base_header);
                            self.wrapped_user_key = Some(wrapped_user_key);
                            self.user_key_nonce = Some(user_key_nonce);
                            self.data_base = DB::default();
                            save_db(data_base_header, encrypt_db(&DB::default(), &public_key)).expect("unreachable");
                            self.public_key = Some(public_key);
                            self.window_open_list.login = true;
                            self.login = true;
                        } else {
                            self.string_values.master_login.password.zeroize();
                            self.string_values.master_login.recheck_password.zeroize();
                            self.string_values.master_login.error_message = "password is mismatch".to_string();
                            return;
                        }
                    }
                    ui.label(&self.string_values.master_login.warning_message);
                });
            },
        );
    }
    
    fn graphical_user_interface_change_master_password(&mut self, context: &Context, button: egui::Response) {
        CommandBuilder::new("change master password", "change master password")
            .sensitive_input("master password", &mut self.string_values.command_value.change_master_password.password)
            .database(&mut self.data_base).user_key_mut(self.wrapped_user_key.as_mut().expect("unreachable")).user_key_nonce_mut(self.user_key_nonce.as_mut().expect("unreachable"))
            .execute(|inputs, data_base, _, wrapped_user_key_mut, _, user_key_nonce_mut| {
                let data_base = data_base.expect("unreachable");
                if let Err(error) = master_pw_validation(inputs[0].value) {
                    return Err(error.into());
                }
                let (public_key, salt) = change_master_pw(data_base, inputs[0].value.take(), wrapped_user_key_mut.expect("unreachable"), user_key_nonce_mut.expect("unreachable"))?;

                self.data_base_header.expect("unreachable").master_pw_salt = salt;
                self.public_key = Some(public_key);
                
                save_db(self.data_base_header.as_mut().expect("unreachable"), encrypt_db(data_base, self.public_key.as_ref().expect("unreachable")))?;
                mark_as_graceful_exited_to_file()?;
                Ok(())
            })
            .on_success(|_| {}).error_message(&mut self.string_values.command_value.change_master_password.error_message)
            .show(context, button, &mut self.window_open_list.change_master_password);
    }

    fn save_data_base(&mut self) -> Result<(), SaveError>{
        let encrypt_db = encrypt_db(&self.data_base, self.public_key.as_ref().ok_or(SaveError::NotingPublicKey)?);
        save_db(self.data_base_header.as_mut().ok_or(SaveError::NothingDataBaseHeader)?, encrypt_db).map_err(SaveError::from)
    }

    fn login(&mut self, ctx: &Context) {
        match load_db() {
            Ok((user_warn, data_base_header, encrypted_data_base)) => {
                self.data_base_header = Some(data_base_header);
                self.string_values.master_login.warning_message = match user_warn {
                    Some(warning) => warning.to_string(),
                    None => String::new(),
                };
                match encrypted_data_base {
                    Some(encrypted_data_base) => {
                        self.existing_user(ctx, &encrypted_data_base);
                    }
                    None => {
                        self.first_login(ctx, &mut self.data_base_header.expect("unreachable"));
                    }
                }
            }
            Err(err) => {
                ctx.show_viewport_immediate(
                    egui::ViewportId::from_hash_of("master_login_err"),
                    egui::ViewportBuilder::default().with_title("error").with_always_on_top().with_inner_size([350.0, 25.0]),
                    |ctx, _| {
                        if ctx.input(|input_state| input_state.viewport().close_requested()) {
                            self.window_open_list.root = false;
                            return
                        }
                        egui::CentralPanel::default().show(ctx, |ui| {
                            ui.label(format!("Error loading db: {}", err));
                        });
                    },
                );
                return
            }
        };
        return
    }
}


impl eframe::App for GraphicalUserInterface {
    fn update(&mut self, ctx: &Context, _frame: &mut eframe::Frame) {
        if ctx.input(|input| input.viewport().close_requested()) && self.window_open_list.root {
            ctx.send_viewport_cmd(ViewportCommand::CancelClose);
            self.window_open_list.root = false;
        }

        if !self.window_open_list.root {
            if check_can_directly_exit() {
                ctx.send_viewport_cmd(ViewportCommand::Close)
            }
            ctx.show_viewport_immediate(
                egui::ViewportId::from_hash_of("close"),
                egui::ViewportBuilder::default().with_title("close"),
                |ctx, _| {
                    egui::CentralPanel::default().show(ctx, |ui| {
                        ui.horizontal(|ui| {
                            if ui.button("cancel").clicked() {
                                self.window_open_list.root = true;
                                return;
                            }
                            if ui.button("save on exit").clicked() {
                                if self.save_data_base().is_err() {
                                    self.string_values.save_error = "failed save".to_string();
                                } else {
                                    self.string_values.save_error = "saved".to_string();
                                    self.window_open_list.root = false;
                                    ctx.send_viewport_cmd(ViewportCommand::Close);
                                }
                            }
                            if ui.button("noting save").clicked() {
                                self.window_open_list.root = false;
                                ctx.send_viewport_cmd(ViewportCommand::Close);
                            }
                        });
                        ui.label(&self.string_values.save_error);
                    });
                }
            );
        }

        if !self.login {
            self.login(ctx);
            return;
        }
        ctx.send_viewport_cmd(ViewportCommand::Title("비밀번호 관리자".to_string()));
        ctx.send_viewport_cmd(ViewportCommand::InnerSize([700.0, 700.0].into()));
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.horizontal(|ui| {
                let save_data_base = ui.button("save data base");
                if save_data_base.clicked() {
                    match self.save_data_base() {
                        Ok(()) => { self.string_values.save_data_base_label = "saved data base".to_string(); }
                        Err(error) => { self.string_values.save_data_base_label = error.to_string(); }
                    }
                }
                ui.label(&self.string_values.save_data_base_label);
            });

            ui.horizontal(|ui| {
                let add_user_password_button = ui.button("add user password").on_hover_text("add user password");
                let change_user_password_button = ui.button("change user password").on_hover_text("change user password");
                let remove_user_password_button = ui.button("remove user password").on_hover_text("remove user password");
                let change_master_password_button = ui.button("change master password").on_hover_text("change master password");
                add_user_password(
                    ctx,
                    add_user_password_button,
                    &mut self.string_values.command_value.add_user_password.site_name,
                    &mut self.string_values.command_value.add_user_password.identifier,
                    &mut self.string_values.command_value.add_user_password.password,
                    &mut self.data_base,
                    self.wrapped_user_key.as_ref().expect("unreachable"),
                    self.user_key_nonce.as_ref().expect("unreachable"),
                    &mut self.string_values.command_value.add_user_password.error_message,
                    &mut self.window_open_list.add_user_password
                );
                change_user_password(
                    ctx,
                    change_user_password_button,
                    &mut self.string_values.command_value.change_user_password.site_name,
                    &mut self.string_values.command_value.change_user_password.identifier,
                    &mut self.string_values.command_value.change_user_password.password,
                    &mut self.data_base,
                    self.wrapped_user_key.as_ref().expect("unreachable"),
                    self.user_key_nonce.as_ref().expect("unreachable"),
                    &mut self.string_values.command_value.change_user_password.error_message,
                    &mut self.window_open_list.change_user_password
                );
                remove_user_password(
                    ctx,
                    remove_user_password_button,
                    &mut self.string_values.command_value.remove_user_password.site_name,
                    &mut self.string_values.command_value.remove_user_password.identifier,
                    &mut self.data_base,
                    &mut self.string_values.command_value.remove_user_password.error_message,
                    &mut self.window_open_list.remove_user_password
                );
                // self.graphical_user_interface_get_user_password(ctx, get_user_password_button);
                self.graphical_user_interface_change_master_password(ctx, change_master_password_button);
            });
            ui.label("search");
            ui.add(egui::TextEdit::singleline(&mut self.string_values.search_data_base));

            let prefix = &self.string_values.search_data_base;
            let lower = SiteName::from_unchecked("", prefix);
            let mut upper_reg = prefix.to_string();
            upper_reg.push(char::MAX);
            let upper = SiteName::from_unchecked("", &upper_reg);

            egui::ScrollArea::vertical().show(ui, |ui| {
                for (site_name, _) in prefix_range(&self.data_base, &self.string_values.search_data_base) {
                    ui.horizontal(|ui| {
                        ui.label(site_name.as_str());
                        let button = ui.button(site_name.as_str().to_string());
                        if button.hovered() {
                            ui.label(site_name.as_str().to_string());
                        }
                        if button.clicked() {
                            self.window_open_list.user_state.update_site_name(site_name.clone(), true);
                        }
                    });
                }
            });

            let user_state = &mut self.window_open_list.user_state;
            let UserState { user_data, site_names } = user_state;
            for (site_name, is_open) in site_names {
                if *is_open {
                    ctx.show_viewport_immediate(
                        egui::ViewportId::from_hash_of(format!("{}_user_data", site_name.as_str())),
                        egui::ViewportBuilder::default().with_title(format!("{} user data", site_name.as_str())),
                        |ctx, _| {
                            if ctx.input(|input_state| { input_state.viewport().close_requested() }) {
                                user_data.remove(site_name);
                                *is_open = false;
                            }

                            egui::CentralPanel::default().show(ctx, |ui| {
                                ui.label(site_name.as_str());
                                ui.horizontal(|ui| {
                                    let add_user_password_button = ui.button("add user password").on_hover_text("add user password");
                                    let change_user_password_button = ui.button("change user password").on_hover_text("change user password");
                                    let remove_user_password_button = ui.button("remove user password").on_hover_text("remove user password");
                                    add_user_password_with_site_name(
                                        ctx,
                                        add_user_password_button,
                                        site_name,
                                        self.string_values.command_value.add_user_password_with_site_name.identifier.entry(site_name.clone()).or_default(),
                                        self.string_values.command_value.add_user_password_with_site_name.password.entry(site_name.clone()).or_default(),
                                        &mut self.data_base,
                                        self.wrapped_user_key.as_ref().expect("unreachable"),
                                        self.user_key_nonce.as_ref().expect("unreachable"),
                                        self.string_values.command_value.add_user_password_with_site_name.error_message.entry(site_name.clone()).or_default(),
                                        self.window_open_list.add_user_password_with_site_name.entry(site_name.clone()).or_default(),
                                    );
                                    change_user_password_with_site_name(
                                        ctx,
                                        change_user_password_button,
                                        site_name,
                                        self.string_values.command_value.change_user_password_with_site_name.identifier.entry(site_name.clone()).or_default(),
                                        self.string_values.command_value.change_user_password_with_site_name.password.entry(site_name.clone()).or_default(),
                                        &mut self.data_base,
                                        self.wrapped_user_key.as_ref().expect("unreachable"),
                                        self.user_key_nonce.as_ref().expect("unreachable"),
                                        self.string_values.command_value.change_user_password_with_site_name.error_message.entry(site_name.clone()).or_default(),
                                        self.window_open_list.change_user_password_with_site_name.entry(site_name.clone()).or_default(),
                                    );
                                    remove_user_password_with_site_name(
                                        ctx,
                                        remove_user_password_button,
                                        site_name,
                                        self.string_values.command_value.remove_user_password_with_site_name.identifier.entry(site_name.clone()).or_default(),
                                        &mut self.data_base,
                                        &mut self.string_values.command_value.remove_user_password_with_site_name.error_message.entry(site_name.clone()).or_default(),
                                        &mut self.window_open_list.remove_user_password_with_site_name.entry(site_name.clone()).or_default(),
                                    );
                                });
                                let Some(passwords) = self.data_base.get_mut(site_name) else {
                                    return;
                                };
                                for (user_identifier, encrypted_password) in passwords.iter_mut() {
                                    egui::Grid::new(user_identifier).num_columns(5).show(ui, |ui| {
                                    ui.label(user_identifier.as_str());
                                        ui.end_row();
                                        let button = ui.button("view password");
                                        if button.is_pointer_button_down_on() {
                                            let mut user_password =
                                                match decrypt_user_pw(site_name, user_identifier, encrypted_password, self.wrapped_user_key.as_ref().expect("unreachable"), self.user_key_nonce.as_ref().expect("unreachable"), ) {
                                                    Ok(password) => password,
                                                    Err(error) => {
                                                        ui.label(format!("error: {}", error));
                                                        return;
                                                    }
                                                };
                                            ui.label(format!("user password: {}", user_password.as_str()));
                                            user_password.zeroize();
                                        }
                                    });
                                }
                            });
                        },
                    );
                }
            }
        });
    }
}

fn add_user_password(
    context: &Context,
    button: egui::Response,
    site_name: &mut String,
    identifier: &mut String,
    password: &mut String,
    data_base: &mut DB,
    wrapped_user_key: &WrappedUserKey,
    user_key_nonce: &UserKeyNonce,
    error_message: &mut String,
    window_open: &mut bool,
) {
    CommandBuilder::new("add user password", "add user password")
        .input("site name", site_name)
        .input("user identifier", identifier)
        .sensitive_input("password", password)
        .database(data_base).user_key(wrapped_user_key).user_key_nonce(user_key_nonce)
        .execute(|inputs, data_base, wrapped_user_key, _, user_key_nonce, _| {
            let site_name = SiteName::new(&inputs[0].value)?;
            let user_identifier = UserID::new(&inputs[1].value)?;
            let user_password = UserPW::new(&inputs[2].value)?;
            add_user_pw(data_base.expect("unreachable"), site_name, user_identifier, user_password, wrapped_user_key.expect("unreachable"), user_key_nonce.expect("unreachable"))?;
            mark_as_ungraceful_exited_to_file()?;
            Ok(())
        })
        .on_success(|_| {}).error_message(error_message)
        .show(context, button, window_open);
}

fn add_user_password_with_site_name(
    context: &Context,
    button: egui::Response,
    site_name: &SiteName,
    identifier: &mut String,
    password: &mut String,
    data_base: &mut DB,
    wrapped_user_key: &WrappedUserKey,
    user_key_nonce: &UserKeyNonce,
    error_message: &mut String,
    window_open: &mut bool,
) {
    CommandBuilder::new("add user password", "add user password")
        .input("user identifier", identifier)
        .sensitive_input("password", password)
        .database(data_base).user_key(wrapped_user_key).user_key_nonce(user_key_nonce)
        .execute(|inputs, data_base, wrapped_user_key, _, user_key_nonce, _| {
            let user_identifier = UserID::new(&inputs[0].value)?;
            let user_password = UserPW::new(&inputs[1].value)?;
            add_user_pw(data_base.expect("unreachable"), site_name.clone(), user_identifier, user_password, wrapped_user_key.expect("unreachable"), user_key_nonce.expect("unreachable"))?;
            mark_as_ungraceful_exited_to_file()?;
            Ok(())
        })
        .on_success(|_| {}).error_message(error_message)
        .show(context, button, window_open);
}

fn change_user_password(
    context: &Context,
    button: egui::Response,
    site_name: &mut String,
    identifier: &mut String,
    password: &mut String,
    data_base: &mut DB,
    wrapped_user_key: &WrappedUserKey,
    user_key_nonce: &UserKeyNonce,
    error_message: &mut String,
    window_open: &mut bool,
) {
    CommandBuilder::new("change user password", "change user password")
        .input("site name", site_name)
        .input("user identifier", identifier)
        .sensitive_input("password", password)
        .database(data_base).user_key(wrapped_user_key).user_key_nonce(user_key_nonce)
        .execute(|inputs, data_base, wrapped_user_key, _, user_key_nonce, _| {
            let site_name = SiteName::new(&inputs[0].value)?;
            let user_identifier = UserID::new(&inputs[1].value)?;
            let user_password = UserPW::new(&inputs[2].value)?;
            change_user_pw(data_base.expect("unreachable"), &site_name, &user_identifier, user_password, wrapped_user_key.expect("unreachable"), user_key_nonce.expect("unreachable"))?;
            mark_as_ungraceful_exited_to_file()?;
            Ok(())
        })
        .on_success(|_| {}).error_message(error_message)
        .show(context, button, window_open);
}

fn change_user_password_with_site_name(
    context: &Context,
    button: egui::Response,
    site_name: &SiteName,
    identifier: &mut String,
    password: &mut String,
    data_base: &mut DB,
    wrapped_user_key: &WrappedUserKey,
    user_key_nonce: &UserKeyNonce,
    error_message: &mut String,
    window_open: &mut bool,
) {
    CommandBuilder::new("change user password", "change user password")
        .input("user identifier", identifier)
        .sensitive_input("password", password)
        .database(data_base).user_key(wrapped_user_key).user_key_nonce(user_key_nonce)
        .execute(|inputs, data_base, wrapped_user_key, _, user_key_nonce, _| {
            let user_identifier = UserID::new(&inputs[0].value)?;
            let user_password = UserPW::new(&inputs[1].value)?;
            change_user_pw(data_base.expect("unreachable"), site_name, &user_identifier, user_password, wrapped_user_key.expect("unreachable"), user_key_nonce.expect("unreachable"))?;
            mark_as_ungraceful_exited_to_file()?;
            Ok(())
        })
        .on_success(|_| {}).error_message(error_message)
        .show(context, button, window_open);
}

fn remove_user_password(
    context: &Context,
    button: egui::Response,
    site_name: &mut String,
    identifier: &mut String,
    data_base: &mut DB,
    error_message: &mut String,
    window_open: &mut bool,
) {
    CommandBuilder::new("remove user password", "remove user password")
        .input("site name", site_name)
        .input("user identifier", identifier)
        .database(data_base)
        .execute(|inputs, data_base, _, _, _, _| {
            let site_name = SiteName::new(&inputs[0].value)?;
            let user_identifier = UserID::new(&inputs[1].value)?;
            remove_user_pw(data_base.expect("unreachable"), &site_name, &user_identifier)?;
            mark_as_ungraceful_exited_to_file()?;
            Ok(())
        })
        .on_success(|_| {}).error_message(error_message)
        .show(context, button, window_open);
}

fn remove_user_password_with_site_name(
    context: &Context,
    button: egui::Response,
    site_name: &SiteName,
    identifier: &mut String,
    data_base: &mut DB,
    error_message: &mut String,
    window_open: &mut bool,
) {
    CommandBuilder::new("remove user password", "remove user password")
        .input("user identifier", identifier)
        .database(data_base)
        .execute(|inputs, data_base, _, _, _, _| {
            let user_identifier = UserID::new(&inputs[0].value)?;
            remove_user_pw(data_base.expect("unreachable"), site_name, &user_identifier)?;
            mark_as_ungraceful_exited_to_file()?;
            Ok(())
        })
        .on_success(|_| {}).error_message(error_message)
        .show(context, button, window_open);
}