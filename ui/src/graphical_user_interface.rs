// todo
// 사이트 이름 + 계정 정보 주면 저장
// 사이트 이름 주면 계정 정보 불러오기
// 사이트 이름 주면 계정 정복 삭제하기

// 흠 뭐부터 하지

use std::collections::{BTreeMap, HashMap};
use std::collections::btree_map::Entry;
use std::num::NonZeroU64;
use eframe::{
    egui::TextBuffer,
    egui::{Context, ViewportCommand, self},
};
use eframe::egui::UserData;
use zeroize::Zeroize;
use engine::{
    header::DBHeader,
    file_io::FileIOError,
    user_secrets::WrappedUserKey,
    file_io::{load_db, save_db},
    data_base::{prefix_range, add_user_pw, change_user_pw, get_user_pw, remove_user_pw, SiteName, UserID, UserPW, DB},
    master_secrets::{change_master_pw, encrypt_db, decrypt_db, master_pw_validation, first_login, general_login, EncryptedDB, PubKey, SecKey},
};
use engine::data_base::DBIOError;
use engine::user_secrets::decrypt_user_pw;
use crate::command_builder::{CommandBuilder, CommandValue};

#[derive(Default)]
struct UserState {
    site_name: BTreeMap<SiteName, bool>,
    user_data: BTreeMap<SiteName, HashMap<UserID, bool>>,
}

impl UserState {
    fn update_site_name(&mut self, site_name: SiteName, value: bool) {
        self.site_name.insert(site_name, value);
    }

    fn get_site_name(&self, site_name: &SiteName) -> Option<&bool> {
        self.site_name.get(site_name)
    }

    fn get_mut_site_name(&mut self, site_name: &SiteName) -> Option<&mut bool> {
        self.site_name.get_mut(site_name)
    }

    fn entry_site_name(&mut self, site_name: SiteName) -> Entry<'_, SiteName, bool> {
        self.site_name.entry(site_name)
    }

    fn update_user_data(&mut self, site_name: SiteName, user_id: UserID, value: bool) {
        if let Some(data) = self.user_data.get_mut(&site_name) {
            if value {
                self.site_name.insert(site_name.clone(), true);
            }
            data.insert(user_id, value);
        }
    }

    fn get_user_data(&self, site_name: &SiteName, user_id: &UserID) -> Option<&bool> {
        self.user_data.get(site_name).and_then(|data| data.get(user_id))
    }
}

struct WindowOpenList {
    root: bool,
    master_login: bool,
    login: bool,
    add_user_password: bool,
    change_user_password: bool,
    remove_user_password: bool,
    get_user_password: bool,
    change_master_password: bool,
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
            get_user_password: false,
            change_master_password: false,
            user_state: Default::default()
        }
    }
}

#[derive(Default)]
struct StringValues {
    password: String,
    recheck_password: String,
    global_error_message: String,
    search_data_base: String,
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

pub struct GraphicalUserInterface {
    login: bool,
    string_values: StringValues,
    window_open_list: WindowOpenList,
    data_base: DB,
    wrapped_user_key: Option<WrappedUserKey>,
    get_user_password_user_password: Option<UserPW>,
    data_base_header: Option<DBHeader>,
    public_key: Option<PubKey>,
    secret_key: Option<SecKey>,
}

impl GraphicalUserInterface {
    fn graphical_user_interface_not_first_login(&mut self, context: &Context, encrypted_data_base: &EncryptedDB) {
        context.show_viewport_immediate(
            egui::ViewportId::from_hash_of("master_login"),
            egui::ViewportBuilder::default().with_title("마스터 로그인").with_inner_size([300.0, 150.0]),
            |ctx, _| {
                if ctx.input(|i| i.viewport().close_requested()) {
                    self.window_open_list.root = false;
                }
                egui::CentralPanel::default().show(ctx, |ui| {
                    ui.label("input master password");
                    ui.add(egui::TextEdit::singleline(&mut self.string_values.password).password(true));
                    ui.label("input recheck master password");
                    ui.add(egui::TextEdit::singleline(&mut self.string_values.recheck_password).password(true));
                    ui.label(&self.string_values.global_error_message);
                    if ui.button("login").clicked() {
                        if self.string_values.password != self.string_values.recheck_password {
                            self.string_values.global_error_message = "invalid password".to_string();
                            return;
                        }
                        let (secret_key, public_key, wrapped_user_key) = match general_login(&mut self.string_values.password.take(), &self.data_base_header.unwrap().master_pw_salt) {
                            Ok(value) => {
                                self.string_values.password.zeroize();
                                self.string_values.recheck_password.zeroize();
                                value
                            },
                            Err(error) => {
                                self.string_values.global_error_message = error.to_string();
                                self.string_values.password.zeroize();
                                self.string_values.recheck_password.zeroize();
                                return;
                            }
                        };
                        let decrypted_data_base = match decrypt_db(&encrypted_data_base, secret_key) {
                            Ok(decrypted_data_base) => decrypted_data_base,
                            Err(error) => {
                                self.string_values.global_error_message = error.to_string();
                                return;
                            }
                        };
                        self.data_base = decrypted_data_base;
                        self.public_key = Some(public_key);
                        self.wrapped_user_key = Some(wrapped_user_key);
                        self.window_open_list.master_login = false;
                        self.login = true;
                    }
                });
            },
        );
    }

    fn graphical_user_interface_first_login(&mut self, context: &Context, data_base_header: &mut DBHeader) {
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
                    ui.add(egui::TextEdit::singleline(&mut self.string_values.password).password(true));
                    ui.label("recheck master password");
                    ui.add(egui::TextEdit::singleline(&mut self.string_values.recheck_password).password(true));
                    ui.label(&self.string_values.global_error_message);
                    if ui.button("Accept").clicked() {
                        if let Err(err) = master_pw_validation(&self.string_values.password) {
                            self.string_values.global_error_message = format!("Master password validation error: {}", err);
                            self.string_values.password.zeroize();
                            self.string_values.recheck_password.zeroize();
                            return;
                        }
                        if self.string_values.password == self.string_values.recheck_password {
                            let (public_key, data_base_header_salt, wrapped_user_key) = first_login(self.string_values.password.take());
                            self.string_values.password.zeroize();
                            self.string_values.recheck_password.zeroize();
                            data_base_header.master_pw_salt = data_base_header_salt;
                            self.data_base_header = Some(*data_base_header);
                            self.wrapped_user_key = Some(wrapped_user_key);
                            self.data_base = DB::default();
                            save_db(data_base_header, encrypt_db(&DB::default(), &public_key)).unwrap();
                            self.public_key = Some(public_key);
                            self.window_open_list.login = true;
                            self.login = true;
                        } else {
                            self.string_values.password.zeroize();
                            self.string_values.recheck_password.zeroize();
                            self.string_values.global_error_message = "password is mismatch".to_string();
                            return;
                        }
                    }
                });
            }
        );
    }

    fn graphical_user_interface_add_user_password(&mut self, context: &Context, button: egui::Response) {
        CommandBuilder::new("add user password", "add user password")
            .input("site name", &mut self.string_values.command_value.add_user_password.site_name)
            .input("user identifier", &mut self.string_values.command_value.add_user_password.identifier)
            .sensitive_input("password", &mut self.string_values.command_value.add_user_password.password)
            .database(&mut self.data_base).user_key(self.wrapped_user_key.as_ref().unwrap())
            .execute(|inputs, data_base, wrapped_user_key, _| {
                let site_name = SiteName::new(&inputs[0].value)?;
                let user_identifier = UserID::new(&inputs[1].value)?;
                let user_password = UserPW::new(&inputs[2].value)?;
                add_user_pw(data_base.unwrap(), site_name, user_identifier, user_password, wrapped_user_key.unwrap())?;
                Ok(())
            })
            .on_success(|_| {}).error_message(&mut self.string_values.global_error_message)
            .show(context, button, &mut self.window_open_list.add_user_password);
    }

    fn graphical_user_interface_change_user_password(&mut self, context: &Context, button: egui::Response) {
        CommandBuilder::new("change user password", "change user password")
            .input("site name", &mut self.string_values.command_value.change_user_password.site_name)
            .input("user identifier", &mut self.string_values.command_value.change_user_password.identifier)
            .sensitive_input("password", &mut self.string_values.command_value.change_user_password.password)
            .database(&mut self.data_base).user_key(self.wrapped_user_key.as_ref().unwrap())
            .execute(|inputs, data_base, wrapped_user_key, _| {
                let site_name = SiteName::new(&inputs[0].value)?;
                let user_identifier = UserID::new(&inputs[1].value)?;
                let user_password = UserPW::new(&inputs[2].value)?;
                change_user_pw(data_base.unwrap(), &site_name, &user_identifier, user_password, wrapped_user_key.unwrap())?;
                Ok(())
            })
            .on_success(|_| {}).error_message(&mut self.string_values.global_error_message)
            .show(context, button, &mut self.window_open_list.change_user_password);
    }

    fn graphical_user_interface_remove_user_password(&mut self, context: &Context, button: egui::Response) {
        CommandBuilder::new("remove user password", "remove user password")
            .input("site name", &mut self.string_values.command_value.remove_user_password.site_name)
            .input("user identifier", &mut self.string_values.command_value.remove_user_password.identifier)
            .database(&mut self.data_base)
            .execute(|inputs, data_base, _, _| {
                let site_name = SiteName::new(&inputs[0].value)?;
                let user_identifier = UserID::new(&inputs[1].value)?;
                remove_user_pw(data_base.unwrap(), &site_name, &user_identifier)?;
                Ok(())
            })
            .on_success(|_| {}).error_message(&mut self.string_values.global_error_message)
            .show(context, button, &mut self.window_open_list.remove_user_password);
    }

    fn graphical_user_interface_get_user_password(&mut self, context: &Context, button: egui::Response) {
        CommandBuilder::new("get user password", "get user password")
            .input("site name", &mut self.string_values.command_value.get_user_password.site_name)
            .input("user identifier", &mut self.string_values.command_value.get_user_password.identifier)
            .database(&mut self.data_base).user_key(self.wrapped_user_key.as_ref().unwrap())
            .execute(|inputs, data_base, wrapped_user_key, _| {
                let site_name = SiteName::new(&inputs[0].value)?;
                let user_identifier = UserID::new(&inputs[1].value)?;
                let password = get_user_pw(data_base.unwrap(), &site_name, &user_identifier, wrapped_user_key.unwrap())?;
                Ok(password)
            })
            .on_success(|password| {
                self.get_user_password_user_password = Some(password);
            })
            .error_message(&mut self.string_values.global_error_message)
            .show(context, button, &mut self.window_open_list.get_user_password);
    }

    fn graphical_user_interface_change_master_password(&mut self, context: &Context, button: egui::Response) {
        CommandBuilder::new("change master password", "change master password")
            .sensitive_input("master password", &mut self.string_values.command_value.change_master_password.password)
            .database(&mut self.data_base).user_key_mut(self.wrapped_user_key.as_mut().unwrap())
            .execute(|inputs, data_base, _, wrapped_user_key_mut| {
                if let Err(error) = master_pw_validation(inputs[0].value) {
                    return Err(error.into());
                }
                let (public_key, salt) = change_master_pw(data_base.unwrap(), inputs[0].value.take(), wrapped_user_key_mut.unwrap())?;
                self.public_key = Some(public_key);
                self.data_base_header.unwrap().master_pw_salt = salt;
                Ok(())
            })
            .on_success(|_| {}).error_message(&mut self.string_values.global_error_message)
            .show(context, button, &mut self.window_open_list.change_master_password);
    }

    fn graphical_user_interface_save_data_base(&self) -> Result<(), FileIOError> {
        save_db(&mut self.data_base_header.unwrap(), encrypt_db(&self.data_base, self.public_key.as_ref().unwrap()))
    }

    fn graphical_user_interface_exit_application_with_save_data_base(&mut self) -> String {
        match save_db(&mut self.data_base_header.unwrap(), encrypt_db(&self.data_base, self.public_key.as_ref().unwrap())) {
            Ok(_) => {
                self.window_open_list.root = false;
                "Successfully saved the database".to_string()
            },
            Err(error) => error.to_string(),
        }
    }

    fn graphical_user_interface_exit_application_with_out_save_data_base(&mut self) {
        self.window_open_list.root = false;
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
            login: false,
            string_values: Default::default(),
            window_open_list: Default::default(),
            data_base: Default::default(),
            wrapped_user_key: None,
            get_user_password_user_password: None,
            data_base_header: None,
            public_key: None,
            secret_key: None,
        }
    }
}

impl eframe::App for GraphicalUserInterface {
    fn update(&mut self, ctx: &Context, _frame: &mut eframe::Frame) {
        if !self.window_open_list.root {
            let encrypted_data_base = encrypt_db(&self.data_base, &self.public_key.as_ref().unwrap());
            save_db(&mut self.data_base_header.unwrap(), encrypted_data_base).unwrap();
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
                            }
                        );
                    }
                    match encrypted_data_base {
                        Some(encrypted_data_base) => {
                            self.graphical_user_interface_not_first_login(ctx, &encrypted_data_base);
                        }
                        None => {
                            self.graphical_user_interface_first_login(ctx, &mut self.data_base_header.unwrap());
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
            return;
        }
        ctx.send_viewport_cmd(ViewportCommand::Title("비밀번호 관리자".to_string()));
        ctx.send_viewport_cmd(ViewportCommand::InnerSize([700.0, 700.0].into()));
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.horizontal(|ui| {
                let add_user_password_button = ui.button("add user password").on_hover_text("add user password");
                let change_user_password_button = ui.button("change user password").on_hover_text("change user password");
                let remove_user_password_button = ui.button("remove user password").on_hover_text("remove user password");
                let get_user_password_button = ui.button("get user password").on_hover_text("get user password");
                let change_master_password_button = ui.button("change master password").on_hover_text("change master password");
                self.graphical_user_interface_add_user_password(ctx, add_user_password_button);
                self.graphical_user_interface_change_user_password(ctx, change_user_password_button);
                self.graphical_user_interface_remove_user_password(ctx, remove_user_password_button);
                self.graphical_user_interface_get_user_password(ctx, get_user_password_button);
                self.graphical_user_interface_change_master_password(ctx, change_master_password_button);
            });
            ui.label("search");
            ui.add(egui::TextEdit::singleline(&mut self.string_values.search_data_base));
            egui::ScrollArea::vertical().show(ui, |ui| {
                for (site_name, user_data) in prefix_range(&self.data_base, &self.string_values.search_data_base) {
                    egui::Grid::new("user_data").show(ui, |ui| {
                        ui.label(site_name.as_str());
                        let button = ui.button(format!("{}", site_name.as_str()));
                        if button.hovered() {
                            ui.label(format!("{}", site_name.as_str()));
                        }
                        if button.clicked() {
                            match self.window_open_list.user_state.entry_site_name(site_name.clone()) {
                                Entry::Occupied(mut entry) => *entry.get_mut() = true,
                                Entry::Vacant(entry) => { entry.insert(true); }
                            }
                        }
                        if *self.window_open_list.user_state.get_site_name(site_name).unwrap_or(&false) {
                            ctx.show_viewport_immediate(
                                egui::ViewportId::from_hash_of(format!("{}_user_data", site_name.as_str())),
                                egui::ViewportBuilder::default().with_title(format!("{} user data", site_name.as_str())),
                                |ctx, _| {
                                    if ctx.input(|input_state| input_state.viewport().close_requested()) {
                                        match self.window_open_list.user_state.entry_site_name(site_name.clone()) {
                                            Entry::Occupied(mut entry) => *entry.get_mut() = false,
                                            Entry::Vacant(entry) => { entry.insert(false); }
                                        }
                                    }

                                    egui::CentralPanel::default().show(ctx, |ui| {
                                        ui.label(format!("{}", site_name.as_str()));
                                        for (user_identifier, encrypted_password) in user_data {
                                            egui::Grid::new(format!("{}", user_identifier.as_str())).show(ui, |ui| {
                                                ui.label(format!("User identifier: {}", user_identifier.as_str()));
                                                let button = ui.button(format!("{}", user_identifier.as_str()));
                                                if button.hovered() {}
                                                if button.clicked() {
                                                    let mut user_password = match decrypt_user_pw(site_name, user_identifier, encrypted_password, self.wrapped_user_key.as_ref().unwrap()) {
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
                                    })
                                }
                            );
                        }
                    });
                }
            });
        });
    }
}
