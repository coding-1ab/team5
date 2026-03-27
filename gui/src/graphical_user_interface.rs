use crate::command_builder::{CommandBuilder, CommandValue};
use anyhow::anyhow;
use eframe::egui::{ViewportBuilder, ViewportId};
use eframe::{
    egui::TextBuffer,
    egui::{self, Context, ViewportCommand},
};
use engine::{
    data_base::{
        DB, SiteName, UserID, UserPW, add_user_pw, change_user_pw, get_user_pw, prefix_range,
        remove_user_pw,
    },
    file_io::{
        DB_BAK_FILE, DB_FILE, FileIOError, check_can_directly_exit, load_db,
        mark_as_graceful_exited_to_file, mark_as_ungraceful_exited_to_file, save_db,
    },
    header::DBHeader,
    master_secrets::{
        EncryptedDB, change_master_pw, decrypt_db, encrypt_db, first_login, general_login,
        master_pw_validation,
    },
    sodium::rust_wrappings::x25519::PubKey,
    user_secrets::{SessionKeyNonce, WrappedSessionKey},
};
use std::{
    collections::{BTreeMap, HashMap},
    error::Error,
    fmt::Display,
    fs,
};
use zeroize::Zeroize;

#[derive(Debug)]
enum SaveError {
    FileIOError(FileIOError),
    NotingPublicKey,
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

struct WindowOpenList {
    root: bool,
    master_login: bool,
    login: bool,
    add_user_password: bool,
    change_user_password: bool,
    remove_user_password: bool,
    change_master_password: bool,
    add_user_password_with_site_name: BTreeMap<SiteName, bool>,
    change_user_password_with_site_name: BTreeMap<SiteName, bool>,
    remove_user_password_with_site_name: BTreeMap<SiteName, bool>,
    change_user_password_with_site_name_with_user_identifier:
        BTreeMap<SiteName, HashMap<UserID, bool>>,
    remove_user_password_with_site_name_with_user_identifier:
        BTreeMap<SiteName, HashMap<UserID, bool>>,
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
            change_master_password: false,
            add_user_password_with_site_name: BTreeMap::new(),
            change_user_password_with_site_name: BTreeMap::new(),
            remove_user_password_with_site_name: BTreeMap::new(),
            change_user_password_with_site_name_with_user_identifier: BTreeMap::new(),
            remove_user_password_with_site_name_with_user_identifier: BTreeMap::new(),
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
    reset_error: String,
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
    data_base_header: DBHeader,
    key: Option<(WrappedSessionKey, SessionKeyNonce)>,
    public_key: Option<PubKey>,
}

impl GraphicalUserInterface {
    fn existing_user(&mut self, context: &Context, encrypted_data_base: &EncryptedDB) {
        context.show_viewport_immediate(
            ViewportId::from_hash_of("master_login"),
            ViewportBuilder::default()
                .with_title("마스터 로그인")
                .with_inner_size([300.0, 175.0]),
            |ctx, _| {
                if ctx.input(|i| i.viewport().close_requested()) {
                    self.window_open_list.root = false;
                }
                egui::CentralPanel::default().show(ctx, |ui| {
                    ui.label("input master password");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.string_values.master_login.password)
                            .password(true),
                    );
                    ui.label(&self.string_values.master_login.error_message);
                    if ui.button("login").clicked() {
                        loading(context);
                        if let Err(error) =
                            master_pw_validation(&self.string_values.master_login.password)
                        {
                            self.string_values.master_login.error_message = error.to_string();
                            return;
                        }
                        let (secret_key, public_key, wrapped_session_key, session_key_nonce) =
                            general_login(
                                &mut self.string_values.master_login.password,
                                &self.data_base_header.master_pw_salt,
                            );
                        self.string_values.master_login.password.zeroize();
                        self.string_values.master_login.recheck_password.zeroize();
                        let decrypted_data_base = match decrypt_db(encrypted_data_base, secret_key)
                        {
                            Ok(decrypted_data_base) => decrypted_data_base,
                            Err(error) => {
                                self.string_values.master_login.error_message = error.to_string();
                                return;
                            }
                        };
                        self.data_base = decrypted_data_base;
                        self.public_key = Some(public_key);
                        self.key = Some((wrapped_session_key, session_key_nonce));
                        self.window_open_list.master_login = false;
                        self.login = true;
                    }
                    if ui.button("reset").clicked() {
                        self.window_open_list.reset = true;
                    }
                    if self.window_open_list.reset {
                        ctx.show_viewport_immediate(
                            ViewportId::from_hash_of("reset"),
                            ViewportBuilder::default().with_title("reset"),
                            |ctx, _| {
                                egui::CentralPanel::default().show(ctx, |ui| {
                                    ui.label("리셋하겠습니까? 복구할 수 없습니다.");
                                    ui.horizontal(|ui| {
                                        if ui.button("submit").clicked() {
                                            match fs::remove_file(DB_FILE)
                                                .and_then(|_| fs::remove_file(DB_BAK_FILE))
                                            {
                                                Ok(_) => self.window_open_list.reset = false,
                                                Err(error) => {
                                                self.string_values.save_error =
                                                        error.to_string();
                                                    return;
                                                }
                                            }
                                        }
                                        if ui.button("cancel").clicked() {
                                            self.window_open_list.reset = false;
                                        }
                                        ui.label(&self.string_values.reset_error);
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

    fn first_login(&mut self, context: &Context) {
        context.show_viewport_immediate(
            ViewportId::from_hash_of("first_master_login"),
            ViewportBuilder::default()
                .with_title("첫 마스터 로그인")
                .with_inner_size([300.0, 175.0]),
            |ctx, _| {
                if ctx.input(|input_state| input_state.viewport().close_requested()) {
                    self.window_open_list.root = false;
                    return;
                }
                egui::CentralPanel::default().show(ctx, |ui| {
                    ui.label("input new master password");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.string_values.master_login.password)
                            .password(true),
                    );
                    ui.label("recheck master password");
                    ui.add(
                        egui::TextEdit::singleline(
                            &mut self.string_values.master_login.recheck_password,
                        )
                        .password(true),
                    );
                    ui.label(&self.string_values.master_login.error_message);
                    if ui.button("Accept").clicked() {
                        loading(context);
                        if let Err(err) =
                            master_pw_validation(&self.string_values.master_login.password)
                        {
                            self.string_values.master_login.error_message =
                                format!("Master password validation error: {}", err);
                            self.string_values.master_login.password.zeroize();
                            self.string_values.master_login.recheck_password.zeroize();
                            return;
                        }
                        if self.string_values.master_login.password
                            == self.string_values.master_login.recheck_password
                        {
                            let (
                                public_key,
                                data_base_header_salt,
                                wrapped_session_key,
                                session_key_nonce,
                            ) = first_login(self.string_values.master_login.password.take());
                            self.string_values.master_login.password.zeroize();
                            self.string_values.master_login.recheck_password.zeroize();
                            self.data_base_header.master_pw_salt = data_base_header_salt;
                            self.key = Some((wrapped_session_key, session_key_nonce));
                            self.data_base = DB::default();
                            save_db(
                                &mut self.data_base_header,
                                encrypt_db(&self.data_base, &public_key),
                            )
                            .expect("unreachable");
                            self.public_key = Some(public_key);
                            self.window_open_list.login = true;
                            self.login = true;
                        } else {
                            self.string_values.master_login.password.zeroize();
                            self.string_values.master_login.recheck_password.zeroize();
                            self.string_values.master_login.error_message =
                                "password is mismatch".to_string();
                            return;
                        }
                    }
                    ui.label(&self.string_values.master_login.warning_message);
                });
            },
        );
    }

    fn login(&mut self, ctx: &Context) {
        match load_db() {
            Ok((user_warning, data_base_header, encrypted_data_base)) => {
                self.data_base_header = data_base_header;
                if let Some(user_warning) = user_warning {
                    self.string_values.master_login.warning_message = user_warning.to_string();
                }
                match encrypted_data_base {
                    Some(encrypted_data_base) => {
                        self.existing_user(ctx, &encrypted_data_base);
                    }
                    None => {
                        self.first_login(ctx);
                    }
                }
            }
            Err(err) => {
                ctx.show_viewport_immediate(
                    ViewportId::from_hash_of("master_login_err"),
                    ViewportBuilder::default()
                        .with_title("error")
                        .with_always_on_top()
                        .with_inner_size([350.0, 25.0]),
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
            }
        };
    }

    fn graphical_user_interface_change_master_password(
        &mut self,
        context: &Context,
        button: egui::Response,
    ) {
        CommandBuilder::new("change master password", "change master password")
            .sensitive_input(
                "master password",
                &mut self
                    .string_values
                    .command_value
                    .change_master_password
                    .password,
            )
            .set_database(&mut self.data_base)
            .set_key_mut(self.key.as_mut().expect("unreachable"))
            .execute(|inputs, data_base, _, key_mut| {
                let data_base = data_base.expect("unreachable");
                if let Err(error) = master_pw_validation(inputs[0].value) {
                    return Err(error.into());
                }
                let Some((wrapped_session_key, session_key_nonce)) = key_mut else {
                    return Err(anyhow!("unreachable"));
                };
                loading(context);
                let (public_key, salt) = change_master_pw(
                    data_base,
                    inputs[0].value.take(),
                    wrapped_session_key,
                    session_key_nonce,
                )?;

                self.data_base_header.master_pw_salt = salt;
                self.public_key = Some(public_key);

                save_db(
                    &mut self.data_base_header,
                    encrypt_db(data_base, self.public_key.as_ref().expect("unreachable")),
                )?;
                mark_as_graceful_exited_to_file()?;
                Ok(())
            })
            .on_success(|_| {})
            .error_message(
                &mut self
                    .string_values
                    .command_value
                    .change_master_password
                    .error_message,
            )
            .show(
                context,
                button,
                &mut self.window_open_list.change_master_password,
            );
    }

    fn save_data_base(&mut self) -> Result<(), SaveError> {
        let encrypt_db = encrypt_db(
            &self.data_base,
            self.public_key.as_ref().ok_or(SaveError::NotingPublicKey)?,
        );
        save_db(&mut self.data_base_header, encrypt_db).map_err(SaveError::from)
    }

    fn user_main_view(&mut self, ctx: &Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.horizontal(|ui| {
                let save_data_base = ui.button("save data base");
                if save_data_base.clicked() {
                    loading(ctx);
                    match self.save_data_base() {
                        Ok(()) => {
                            self.string_values.save_data_base_label = "saved data base".to_string();
                        }
                        Err(error) => {
                            self.string_values.save_data_base_label = error.to_string();
                        }
                    }
                }
                ui.label(&self.string_values.save_data_base_label);
            });

            ui.horizontal(|ui| {
                let add_user_password_button = ui
                    .button("add user password")
                    .on_hover_text("add user password");
                let change_user_password_button = ui
                    .button("change user password")
                    .on_hover_text("change user password");
                let remove_user_password_button = ui
                    .button("remove user password")
                    .on_hover_text("remove user password");
                let change_master_password_button = ui
                    .button("change master password")
                    .on_hover_text("change master password");
                add_user_password(
                    ctx,
                    add_user_password_button,
                    &mut self.string_values.command_value.add_user_password.site_name,
                    &mut self
                        .string_values
                        .command_value
                        .add_user_password
                        .user_identifier,
                    &mut self.string_values.command_value.add_user_password.password,
                    &mut self.data_base,
                    self.key.as_ref().expect("unreachable"),
                    &mut self
                        .string_values
                        .command_value
                        .add_user_password
                        .error_message,
                    &mut self.window_open_list.add_user_password,
                );
                change_user_password(
                    ctx,
                    change_user_password_button,
                    &mut self
                        .string_values
                        .command_value
                        .change_user_password
                        .site_name,
                    &mut self
                        .string_values
                        .command_value
                        .change_user_password
                        .user_identifier,
                    &mut self
                        .string_values
                        .command_value
                        .change_user_password
                        .password,
                    &mut self.data_base,
                    self.key.as_ref().expect("unreachable"),
                    &mut self
                        .string_values
                        .command_value
                        .change_user_password
                        .error_message,
                    &mut self.window_open_list.change_user_password,
                );
                remove_user_password(
                    ctx,
                    remove_user_password_button,
                    &mut self
                        .string_values
                        .command_value
                        .remove_user_password
                        .site_name,
                    &mut self
                        .string_values
                        .command_value
                        .remove_user_password
                        .user_identifier,
                    &mut self.data_base,
                    &mut self
                        .string_values
                        .command_value
                        .remove_user_password
                        .error_message,
                    &mut self.window_open_list.remove_user_password,
                );
                // self.graphical_user_interface_get_user_password(ctx, get_user_password_button);
                self.graphical_user_interface_change_master_password(
                    ctx,
                    change_master_password_button,
                );
            });
            ui.label("search");
            ui.add(egui::TextEdit::singleline(
                &mut self.string_values.search_data_base,
            ));

            egui::ScrollArea::vertical().show(ui, |ui| {
                for (site_name, _) in
                    prefix_range(&self.data_base, &self.string_values.search_data_base)
                {
                    ui.horizontal(|ui| {
                        ui.label(site_name.as_str());
                        let button = ui.button(site_name.as_str().to_string());
                        if button.hovered() {
                            ui.label(site_name.as_str().to_string());
                        }
                        if button.clicked() {
                            self.window_open_list
                                .user_state
                                .site_names
                                .insert(site_name.clone(), true);
                        }
                    });
                }
            });

            self.user_passwords_windows(ctx);
        });
    }

    fn user_passwords_windows(&mut self, context: &Context) {
        let user_state = &mut self.window_open_list.user_state;
        let UserState {
            user_data,
            site_names,
        } = user_state;
        for (site_name, is_open) in site_names {
            if *is_open {
                context.show_viewport_immediate(
                    ViewportId::from_hash_of(format!("{}_user_data", site_name.as_str())),
                    ViewportBuilder::default().with_title(format!("{} user data", site_name.as_str())),
                    |context, _| {
                        if context.input(|input_state| { input_state.viewport().close_requested() }) {
                            user_data.remove(site_name);
                            *is_open = false;
                        }

                        egui::CentralPanel::default().show(context, |ui| {
                            ui.label(site_name.as_str());
                            ui.horizontal(|ui| {
                                let add_user_password_button = ui.button("add user password").on_hover_text("add user password");
                                let change_user_password_button = ui.button("change user password").on_hover_text("change user password");
                                let remove_user_password_button = ui.button("remove user password").on_hover_text("remove user password");
                                add_user_password_with_site_name(
                                    context,
                                    add_user_password_button,
                                    site_name,
                                    self.string_values.command_value.add_user_password_with_site_name.user_identifier.entry(site_name.clone()).or_default(),
                                    self.string_values.command_value.add_user_password_with_site_name.password.entry(site_name.clone()).or_default(),
                                    &mut self.data_base,
                                    self.key.as_ref().expect("unreachable"),
                                    self.string_values.command_value.add_user_password_with_site_name.error_message.entry(site_name.clone()).or_default(),
                                    self.window_open_list.add_user_password_with_site_name.entry(site_name.clone()).or_default(),
                                );

                                change_user_password_with_site_name(
                                    context,
                                    change_user_password_button,
                                    site_name,
                                    self.string_values.command_value.change_user_password_with_site_name.user_identifier.entry(site_name.clone()).or_default(),
                                    self.string_values.command_value.change_user_password_with_site_name.password.entry(site_name.clone()).or_default(),
                                    &mut self.data_base,
                                    self.key.as_ref().expect("unreachable"),
                                    self.string_values.command_value.change_user_password_with_site_name.error_message.entry(site_name.clone()).or_default(),
                                    self.window_open_list.change_user_password_with_site_name.entry(site_name.clone()).or_default(),
                                );

                                remove_user_password_with_site_name(
                                    context,
                                    remove_user_password_button,
                                    site_name,
                                    self.string_values.command_value.remove_user_password_with_site_name.user_identifier.entry(site_name.clone()).or_default(),
                                    &mut self.data_base,
                                    self.string_values.command_value.remove_user_password_with_site_name.error_message.entry(site_name.clone()).or_default(),
                                    self.window_open_list.remove_user_password_with_site_name.entry(site_name.clone()).or_default(),
                                );
                            });
                            let Some(passwords): Option<Vec<_>> = self.data_base.get(site_name).map(|map| map.keys().cloned().collect()) else {
                                return;
                            };
                            egui::ScrollArea::vertical().show(ui, |ui| {
                                for user_identifier in passwords {
                                    ui.vertical(|ui| {
                                        ui.label(user_identifier.as_str());
                                        ui.horizontal(|ui| {
                                            let change_user_password_button = ui.button("change user password");
                                            let remove_user_password_button = ui.button("remove user password");
                                            let view_password_button = ui.button("view password");
                                            change_user_password_with_site_name_with_user_identifier(
                                                context,
                                                change_user_password_button,
                                                site_name,
                                                &user_identifier,
                                                self.string_values.command_value.change_user_password_with_site_name_with_user_identifier.password.entry(site_name.clone()).or_default().entry(user_identifier.clone()).or_default(),
                                                &mut self.data_base,
                                                self.key.as_ref().expect("unreachable"),
                                                self.string_values.command_value.change_user_password_with_site_name_with_user_identifier.error_message.entry(site_name.clone()).or_default().entry(user_identifier.clone()).or_default(),
                                                self.window_open_list.change_user_password_with_site_name_with_user_identifier.entry(site_name.clone()).or_default().entry(user_identifier.clone()).or_default(),
                                            );

                                            remove_user_password_with_site_name_with_user_identifier(
                                                context,
                                                remove_user_password_button,
                                                site_name,
                                                &user_identifier,
                                                &mut self.data_base,
                                                self.string_values.command_value.remove_user_password_with_site_name_with_user_identifier.error_message.entry(site_name.clone()).or_default().entry(user_identifier.clone()).or_default(),
                                                self.window_open_list.remove_user_password_with_site_name_with_user_identifier.entry(site_name.clone()).or_default().entry(user_identifier.clone()).or_default(),
                                            );

                                            if view_password_button.is_pointer_button_down_on() {
                                                let mut user_password = {
                                                    let Some((wrapped_session_key, session_key_nonce)) = &self.key else {
                                                        return;
                                                    };
                                                    match get_user_pw(&self.data_base, site_name, &user_identifier, wrapped_session_key, session_key_nonce) {
                                                        Ok(password) => password,
                                                        Err(error) => {
                                                            ui.label(format!("error: {}", error));
                                                            return;
                                                        }
                                                    }
                                                };
                                                ui.label(format!("user password: {}", user_password.as_str()));
                                                user_password.zeroize();
                                            }
                                        });
                                    });
                                }
                            });
                        });
                    },
                );
            }
        }
    }
}

impl eframe::App for GraphicalUserInterface {
    fn update(&mut self, ctx: &Context, _frame: &mut eframe::Frame) {
        if ctx.input(|input| input.viewport().close_requested()) && self.window_open_list.root {
            ctx.send_viewport_cmd_to(ViewportId::ROOT, ViewportCommand::CancelClose);
            self.window_open_list.root = false;
        }

        if !self.window_open_list.root {
            if check_can_directly_exit() {
                ctx.send_viewport_cmd_to(ViewportId::ROOT, ViewportCommand::Close)
            }
            ctx.show_viewport_immediate(
                ViewportId::from_hash_of("close"),
                ViewportBuilder::default()
                    .with_title("close")
                    .with_inner_size([250.0, 50.0]),
                |ctx, _| {
                    egui::CentralPanel::default().show(ctx, |ui| {
                        ui.horizontal(|ui| {
                            if ui.button("cancel").clicked() {
                                self.window_open_list.root = true;
                                return;
                            }
                            if ui.button("save on exit").clicked() {
                                if let Err(_) = self.save_data_base() {
                                    self.string_values.save_error = "failed save".to_string();
                                } else {
                                    self.string_values.save_error = "saved".to_string();
                                    ctx.send_viewport_cmd_to(
                                        ViewportId::ROOT,
                                        ViewportCommand::Close,
                                    );
                                }
                            }
                            if ui.button("noting save").clicked() {
                                mark_as_graceful_exited_to_file().unwrap();
                                ctx.send_viewport_cmd_to(ViewportId::ROOT, ViewportCommand::Close);
                            }
                        });
                        ui.label(&self.string_values.save_error);
                    });
                },
            );
        }

        if !self.login {
            self.login(ctx);
            return;
        }
        ctx.send_viewport_cmd(ViewportCommand::Title("비밀번호 관리자".to_string()));
        ctx.send_viewport_cmd(ViewportCommand::InnerSize([800.0, 600.0].into()));
        self.user_main_view(ctx);
    }
}

#[allow(clippy::too_many_arguments)]
fn add_user_password(
    context: &Context,
    button: egui::Response,
    site_name: &mut String,
    identifier: &mut String,
    password: &mut String,
    data_base: &mut DB,
    key: &(WrappedSessionKey, SessionKeyNonce),
    error_message: &mut String,
    window_open: &mut bool,
) {
    CommandBuilder::new("add user password", "add user password")
        .input("site name", site_name)
        .input("user identifier", identifier)
        .sensitive_input("password", password)
        .set_database(data_base)
        .set_key(key)
        .execute(|inputs, data_base, key, _| {
            let Some((wrapped_session_key, session_key_nonce)) = key else {
                return Err(anyhow!("unreachable"));
            };
            let site_name = SiteName::new(inputs[0].value)?;
            let user_identifier = UserID::new(inputs[1].value)?;
            let user_password = UserPW::new(inputs[2].value)?;
            add_user_pw(
                data_base.expect("unreachable"),
                site_name,
                user_identifier,
                user_password,
                wrapped_session_key,
                session_key_nonce,
            )?;
            mark_as_ungraceful_exited_to_file()?;
            Ok(())
        })
        .on_success(|_| {})
        .error_message(error_message)
        .show(context, button, window_open);
}

#[allow(clippy::too_many_arguments)]
fn add_user_password_with_site_name(
    context: &Context,
    button: egui::Response,
    site_name: &SiteName,
    identifier: &mut String,
    password: &mut String,
    data_base: &mut DB,
    key: &(WrappedSessionKey, SessionKeyNonce),
    error_message: &mut String,
    window_open: &mut bool,
) {
    CommandBuilder::new("add user password", "add user password")
        .input("user identifier", identifier)
        .sensitive_input("password", password)
        .set_database(data_base)
        .set_key(key)
        .execute(|inputs, data_base, key, _| {
            let Some((wrapped_session_key, session_key_nonce)) = key else {
                return Err(anyhow!("unreachable"));
            };
            let user_identifier = UserID::new(inputs[0].value)?;
            let user_password = UserPW::new(inputs[1].value)?;
            add_user_pw(
                data_base.expect("unreachable"),
                site_name.clone(),
                user_identifier,
                user_password,
                wrapped_session_key,
                session_key_nonce,
            )?;
            mark_as_ungraceful_exited_to_file()?;
            Ok(())
        })
        .on_success(|_| {})
        .error_message(error_message)
        .show(context, button, window_open);
}

#[allow(clippy::too_many_arguments)]
fn change_user_password(
    context: &Context,
    button: egui::Response,
    site_name: &mut String,
    user_identifier: &mut String,
    password: &mut String,
    data_base: &mut DB,
    key: &(WrappedSessionKey, SessionKeyNonce),
    error_message: &mut String,
    window_open: &mut bool,
) {
    CommandBuilder::new("change user password", "change user password")
        .input("site name", site_name)
        .input("user identifier", user_identifier)
        .sensitive_input("password", password)
        .set_database(data_base)
        .set_key(key)
        .execute(|inputs, data_base, key, _| {
            let Some((wrapped_session_key, session_key_nonce)) = key else {
                return Err(anyhow!("unreachable"));
            };
            let site_name = SiteName::new(inputs[0].value)?;
            let user_identifier = UserID::new(inputs[1].value)?;
            let user_password = UserPW::new(inputs[2].value)?;
            change_user_pw(
                data_base.expect("unreachable"),
                &site_name,
                &user_identifier,
                user_password,
                wrapped_session_key,
                session_key_nonce,
            )?;
            mark_as_ungraceful_exited_to_file()?;
            Ok(())
        })
        .on_success(|_| {})
        .error_message(error_message)
        .show(context, button, window_open);
}

#[allow(clippy::too_many_arguments)]
fn change_user_password_with_site_name(
    context: &Context,
    button: egui::Response,
    site_name: &SiteName,
    user_identifier: &mut String,
    password: &mut String,
    data_base: &mut DB,
    key: &(WrappedSessionKey, SessionKeyNonce),
    error_message: &mut String,
    window_open: &mut bool,
) {
    CommandBuilder::new("change user password", "change user password")
        .input("user identifier", user_identifier)
        .sensitive_input("password", password)
        .set_database(data_base)
        .set_key(key)
        .execute(|inputs, data_base, key, _| {
            let Some((wrapped_session_key, session_key_nonce)) = key else {
                return Err(anyhow!("unreachable"));
            };
            let user_identifier = UserID::new(inputs[0].value)?;
            let user_password = UserPW::new(inputs[1].value)?;
            change_user_pw(
                data_base.expect("unreachable"),
                site_name,
                &user_identifier,
                user_password,
                wrapped_session_key,
                session_key_nonce,
            )?;
            mark_as_ungraceful_exited_to_file()?;
            Ok(())
        })
        .on_success(|_| {})
        .error_message(error_message)
        .show(context, button, window_open);
}

#[allow(clippy::too_many_arguments)]
fn change_user_password_with_site_name_with_user_identifier(
    context: &Context,
    button: egui::Response,
    site_name: &SiteName,
    user_identifier: &UserID,
    password: &mut String,
    data_base: &mut DB,
    key: &(WrappedSessionKey, SessionKeyNonce),
    error_message: &mut String,
    window_open: &mut bool,
) {
    CommandBuilder::new("change user password", "change user password")
        .sensitive_input("password", password)
        .set_database(data_base)
        .set_key(key)
        .execute(|inputs, data_base, key, _| {
            let Some((wrapped_session_key, session_key_nonce)) = key else {
                return Err(anyhow!("unreachable"));
            };
            let user_password = UserPW::new(inputs[0].value)?;
            change_user_pw(
                data_base.expect("unreachable"),
                site_name,
                user_identifier,
                user_password,
                wrapped_session_key,
                session_key_nonce,
            )?;
            mark_as_ungraceful_exited_to_file()?;
            Ok(())
        })
        .on_success(|_| {})
        .error_message(error_message)
        .show(context, button, window_open);
}

fn remove_user_password(
    context: &Context,
    button: egui::Response,
    site_name: &mut String,
    user_identifier: &mut String,
    data_base: &mut DB,
    error_message: &mut String,
    window_open: &mut bool,
) {
    CommandBuilder::new("remove user password", "remove user password")
        .input("site name", site_name)
        .input("user identifier", user_identifier)
        .set_database(data_base)
        .execute(|inputs, data_base, _, _| {
            let site_name = SiteName::new(inputs[0].value)?;
            let user_identifier = UserID::new(inputs[1].value)?;
            remove_user_pw(
                data_base.expect("unreachable"),
                &site_name,
                &user_identifier,
            )?;
            mark_as_ungraceful_exited_to_file()?;
            Ok(())
        })
        .on_success(|_| {})
        .error_message(error_message)
        .show(context, button, window_open);
}

fn remove_user_password_with_site_name(
    context: &Context,
    button: egui::Response,
    site_name: &SiteName,
    user_identifier: &mut String,
    data_base: &mut DB,
    error_message: &mut String,
    window_open: &mut bool,
) {
    CommandBuilder::new("remove user password", "remove user password")
        .input("user identifier", user_identifier)
        .set_database(data_base)
        .execute(|inputs, data_base, _, _| {
            let user_identifier = UserID::new(inputs[0].value)?;
            remove_user_pw(data_base.expect("unreachable"), site_name, &user_identifier)?;
            mark_as_ungraceful_exited_to_file()?;
            Ok(())
        })
        .on_success(|_| {})
        .error_message(error_message)
        .show(context, button, window_open);
}

fn remove_user_password_with_site_name_with_user_identifier(
    context: &Context,
    button: egui::Response,
    site_name: &SiteName,
    user_identifier: &UserID,
    data_base: &mut DB,
    error_message: &mut String,
    window_open: &mut bool,
) {
    CommandBuilder::new("remove user password", "remove user password")
        .set_database(data_base)
        .execute(|_, data_base, _, _| {
            remove_user_pw(data_base.expect("unreachable"), site_name, user_identifier)?;
            mark_as_ungraceful_exited_to_file()?;
            Ok(())
        })
        .on_success(|_| {})
        .error_message(error_message)
        .show(context, button, window_open);
}

fn loading(context: &Context) {
    context.show_viewport_immediate(
        ViewportId::from_hash_of("loading"),
        ViewportBuilder::default().with_title("loading"),
        |ctx, _| {
            egui::CentralPanel::default().show(ctx, |ui| {
                ui.label("Loading...");
            });
        },
    )
}
