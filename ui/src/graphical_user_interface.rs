// todo
// 사이트 이름 + 계정 정보 주면 저장
// 사이트 이름 주면 계정 정보 불러오기
// 사이트 이름 주면 계정 정복 삭제하기

// 흠 뭐부터 하지

use std::collections::{BTreeMap, HashMap, btree_map::Entry};
use eframe::{
    egui::TextBuffer,
    egui::{self, Context, ViewportCommand},
};
use engine::file_io::mark_as_graceful_exited_to_file;
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
}

#[derive(Default)]
struct StringValues {
    search_data_base: String,
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
                                        if ui.button("yes").clicked() {
                                            *self = Self::default();
                                            self.window_open_list.reset = false;
                                        }
                                        if ui.button("no").clicked() {
                                            self.window_open_list.reset = false;
                                        }
                                    })
                                })
                            },
                        );
                    }
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
                });
            },
        );
    }

    fn graphical_user_interface_add_user_password(&mut self, context: &Context, button: egui::Response) {
        CommandBuilder::new("add user password", "add user password")
            .input("site name", &mut self.string_values.command_value.add_user_password.site_name)
            .input("user identifier", &mut self.string_values.command_value.add_user_password.identifier)
            .sensitive_input("password", &mut self.string_values.command_value.add_user_password.password)
            .database(&mut self.data_base).user_key(self.wrapped_user_key.as_ref().expect("unreachable")).user_key_nonce(self.user_key_nonce.as_ref().expect("unreachable"))
            .execute(|inputs, data_base, wrapped_user_key, _, user_key_nonce, _| {
                let site_name = SiteName::new(&inputs[0].value)?;
                let user_identifier = UserID::new(&inputs[1].value)?;
                let user_password = UserPW::new(&inputs[2].value)?;
                add_user_pw(data_base.expect("unreachable"), site_name, user_identifier, user_password, wrapped_user_key.expect("unreachable"), user_key_nonce.expect("unreachable"))?;
                Ok(())
            })
            .on_success(|_| {}).error_message(&mut self.string_values.command_value.add_user_password.error_message)
            .show(context, button, &mut self.window_open_list.add_user_password);
    }

    fn change_user_password(&mut self, context: &Context, button: egui::Response) {
        CommandBuilder::new("change user password", "change user password")
            .input("site name", &mut self.string_values.command_value.change_user_password.site_name)
            .input("user identifier", &mut self.string_values.command_value.change_user_password.identifier)
            .sensitive_input("password", &mut self.string_values.command_value.change_user_password.password)
            .database(&mut self.data_base).user_key(self.wrapped_user_key.as_ref().expect("unreachable")).user_key_nonce(self.user_key_nonce.as_ref().expect("unreachable"))
            .execute(|inputs, data_base, wrapped_user_key, _, user_key_nonce, _| {
                let site_name = SiteName::new(&inputs[0].value)?;
                let user_identifier = UserID::new(&inputs[1].value)?;
                let user_password = UserPW::new(&inputs[2].value)?;
                change_user_pw(data_base.expect("unreachable"), &site_name, &user_identifier, user_password, wrapped_user_key.expect("unreachable"), user_key_nonce.expect("unreachable"))?;
                Ok(())
            })
            .on_success(|_| {}).error_message(&mut self.string_values.command_value.change_user_password.error_message)
            .show(context, button, &mut self.window_open_list.change_user_password);
    }

    fn remove_user_password(&mut self, context: &Context, button: egui::Response) {
        CommandBuilder::new("remove user password", "remove user password")
            .input("site name", &mut self.string_values.command_value.remove_user_password.site_name)
            .input("user identifier", &mut self.string_values.command_value.remove_user_password.identifier)
            .database(&mut self.data_base)
            .execute(|inputs, data_base, _, _, _, _| {
                let site_name = SiteName::new(&inputs[0].value)?;
                let user_identifier = UserID::new(&inputs[1].value)?;
                remove_user_pw(data_base.expect("unreachable"), &site_name, &user_identifier)?;
                Ok(())
            })
            .on_success(|_| {}).error_message(&mut self.string_values.command_value.remove_user_password.error_message)
            .show(context, button, &mut self.window_open_list.remove_user_password);
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


impl eframe::App for GraphicalUserInterface {
    fn update(&mut self, ctx: &Context, _frame: &mut eframe::Frame) {
        if !self.window_open_list.root {
            ctx.send_viewport_cmd(ViewportCommand::Close);
        }

        if !self.login {
            match load_db() {
                Ok((user_warn, data_base_header, encrypted_data_base)) => {
                    self.data_base_header = Some(data_base_header);
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
                            },
                        );
                    }
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
                                return;
                            }
                            egui::CentralPanel::default().show(ctx, |ui| {
                                ui.label(format!("Error loading db: {}", err));
                            });
                        },
                    );
                    return;
                }
            };
            return;
        }
        ctx.send_viewport_cmd(ViewportCommand::Title("비밀번호 관리자".to_string()));
        ctx.send_viewport_cmd(ViewportCommand::InnerSize([700.0, 700.0].into()));
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.horizontal(|ui| {
                let change_user_password_button = ui.button("change user password").on_hover_text("change user password");
                let remove_user_password_button = ui.button("remove user password").on_hover_text("remove user password");
                // let get_user_password_button = ui.button("get user password").on_hover_text("get user password");
                let change_master_password_button = ui.button("change master password").on_hover_text("change master password");
                self.change_user_password(ctx, change_user_password_button);
                self.remove_user_password(ctx, remove_user_password_button);
                // self.graphical_user_interface_get_user_password(ctx, get_user_password_button);
                self.graphical_user_interface_change_master_password(ctx, change_master_password_button);
                let add_user_password_button = ui.button("add user password").on_hover_text("add user password");
                self.graphical_user_interface_add_user_password(ctx, add_user_password_button);
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
                    egui::Grid::new("user_data").show(ui, |ui| {
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
                if let Some(passwords) = self.data_base.get_mut(site_name) && *is_open {
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
                                for (user_identifier, encrypted_password) in passwords.iter_mut() {
                                    egui::Grid::new(user_identifier).min_col_width(128.0).show(ui, |ui| {
                                        ui.vertical(|ui| {
                                            ui.label(format!("User identifier\n{}", user_identifier.as_str()));
                                            let button = ui.button("view password");
                                            if button.hovered() {}
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
                                    });
                                }
                            });
                        },
                    );
                }
            }
        });
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        let encrypted_data_base = encrypt_db(&self.data_base, &self.public_key.as_ref().expect("unreachable"));
        save_db(&mut self.data_base_header.expect("unreachable"), encrypted_data_base).expect("unreachable");
    }
}
