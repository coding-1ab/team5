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
use crate::command_builder::{CommandBuilder, CommandValue};
use crate::window::{AddUserPassword, AddUserPasswordWithSiteName, ChangeUserPassword, ChangeUserPasswordWithSiteName, ChangeUserPasswordWithSiteNameWithUserIdentifier, RemoveUserPassword, RemoveUserPasswordWithSiteName, RemoveUserPasswordWithSiteNameWithUserIdentifier, RootSave, RootSaveType};

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

#[derive(Default)]
struct WindowOpenList {
    pub(crate) root: Option<RootSave>,
    login: bool,
    add_user_password: Option<AddUserPassword>,
    change_user_password: Option<ChangeUserPassword>,
    remove_user_password: Option<RemoveUserPassword>,
    change_master_password: bool,
    add_user_password_with_site_name: BTreeMap<SiteName, AddUserPasswordWithSiteName>,
    change_user_password_with_site_name: BTreeMap<SiteName, ChangeUserPasswordWithSiteName>,
    remove_user_password_with_site_name: BTreeMap<SiteName, RemoveUserPasswordWithSiteName>,
    change_user_password_with_site_name_with_user_identifier:
        BTreeMap<SiteName, HashMap<UserID, ChangeUserPasswordWithSiteNameWithUserIdentifier>>,
    remove_user_password_with_site_name_with_user_identifier:
        BTreeMap<SiteName, HashMap<UserID, RemoveUserPasswordWithSiteNameWithUserIdentifier>>,
    reset: bool,
    user_state: UserState,
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
    pub(crate) window_open_list: WindowOpenList,
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
                    self.exit_root(context);
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
                    self.exit_root(context);
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
                            self.exit_root(ctx);
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

    pub(crate) fn save_data_base(&mut self) -> Result<(), SaveError> {
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
                let change_master_password_button = ui.button("change master password").on_hover_text("change master password");
                if ui.button("add user password").on_hover_text("add user password").clicked() {
                    self.window_open_list.add_user_password = Some(AddUserPassword::default());
                }
                if let Some(add_user_password) = &mut self.window_open_list.add_user_password {
                    if !add_user_password.display(ctx, self.key.as_ref().expect("unreachable"), &mut self.data_base) {
                        self.window_open_list.add_user_password = None;
                    }
                }
                if ui.button("change user password").on_hover_text("change user password").clicked() {
                    self.window_open_list.change_user_password = Some(ChangeUserPassword::default());
                }
                if let Some(change_user_password) = &mut self.window_open_list.change_user_password {
                    if !change_user_password.display(ctx, self.key.as_ref().expect("unreachable"), &mut self.data_base) {
                        self.window_open_list.change_user_password = None;
                    }
                }
                if ui.button("remove user password").on_hover_text("remove user password").clicked() {
                    self.window_open_list.remove_user_password = Some(RemoveUserPassword::default());
                }
                if let Some(remove_user_password) = &mut self.window_open_list.remove_user_password {
                    if !remove_user_password.display(ctx, self.key.as_ref().expect("unreachable"), &mut self.data_base) {
                        self.window_open_list.remove_user_password = None;
                    }
                }
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
                                if ui.button("add user password").on_hover_text("add user password").clicked() {
                                    self.window_open_list.add_user_password_with_site_name.insert(site_name.clone(), AddUserPasswordWithSiteName::default());
                                }
                                if let Some(add_user_password_site_name) = self.window_open_list.add_user_password_with_site_name.get_mut(site_name) {
                                    if !add_user_password_site_name.display(context, self.key.as_ref().unwrap(), &mut self.data_base, site_name) {
                                        self.window_open_list.add_user_password_with_site_name.remove(site_name);
                                    }
                                }
                                if ui.button("change user password").on_hover_text("change user password").clicked() {
                                    self.window_open_list.change_user_password_with_site_name.insert(site_name.clone(), ChangeUserPasswordWithSiteName::default());
                                }
                                if let Some(change_user_password_with_site_name) = self.window_open_list.change_user_password_with_site_name.get_mut(site_name) {
                                    if !change_user_password_with_site_name.display(context, self.key.as_ref().unwrap(), &mut self.data_base, site_name) {
                                        self.window_open_list.change_user_password_with_site_name.remove(site_name);
                                    }
                                }
                                if ui.button("remove user password").on_hover_text("remove user password").clicked() {
                                    self.window_open_list.remove_user_password_with_site_name.insert(site_name.clone(), RemoveUserPasswordWithSiteName::default());
                                }
                                if let Some(remove_user_password_with_site_name) = self.window_open_list.remove_user_password_with_site_name.get_mut(site_name) {
                                    if !remove_user_password_with_site_name.display(context, &mut self.data_base, site_name) {
                                        self.window_open_list.remove_user_password_with_site_name.remove(site_name);
                                    }
                                }
                            });
                            let Some(passwords): Option<Vec<_>> = self.data_base.get(site_name).map(|map| map.keys().cloned().collect()) else {
                                return;
                            };
                            egui::ScrollArea::vertical().show(ui, |ui| {
                                for user_identifier in passwords {
                                    ui.vertical(|ui| {
                                        ui.label(user_identifier.as_str());
                                        ui.horizontal(|ui| {
                                            if ui.button("change user password").clicked() {
                                                self.window_open_list.change_user_password_with_site_name_with_user_identifier.entry(site_name.clone()).or_default().entry(user_identifier.clone()).or_default();
                                            }
                                            if let Some(change_user_password_with_size_name_with_user_identifier) = self.window_open_list.change_user_password_with_site_name_with_user_identifier.get_mut(site_name).and_then(|value| value.get_mut(&user_identifier)) {
                                                if !change_user_password_with_size_name_with_user_identifier.display(context, self.key.as_ref().unwrap(), &mut self.data_base, site_name, &user_identifier) {
                                                    self.window_open_list.change_user_password_with_site_name_with_user_identifier.entry(site_name.clone()).or_default().remove(&user_identifier);
                                                }
                                            }
                                            if ui.button("remove user password").clicked() {
                                                self.window_open_list.remove_user_password_with_site_name_with_user_identifier.entry(site_name.clone()).or_default().entry(user_identifier.clone()).or_default();
                                            }
                                            if let Some(remove_user_password_with_size_name_with_user_identifier) = self.window_open_list.remove_user_password_with_site_name_with_user_identifier.get_mut(site_name).and_then(|value| value.get_mut(&user_identifier)) {
                                                if !remove_user_password_with_size_name_with_user_identifier.display(context, &mut self.data_base, site_name, &user_identifier) {
                                                    self.window_open_list.remove_user_password_with_site_name_with_user_identifier.entry(site_name.clone()).or_default().remove(&user_identifier);
                                                }
                                            }
                                            let view_password_button = ui.button("view password");
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


    fn exit_root(&mut self, context: &Context) {
        if check_can_directly_exit() {
            context.send_viewport_cmd_to(ViewportId::ROOT, ViewportCommand::Close)
        }
        self.window_open_list.root = Some(RootSave::default());
    }
}

impl eframe::App for GraphicalUserInterface {
    fn update(&mut self, ctx: &Context, _frame: &mut eframe::Frame) {
        if ctx.input(|input| input.viewport().close_requested()) && self.window_open_list.root.is_none() {
            ctx.send_viewport_cmd_to(ViewportId::ROOT, ViewportCommand::CancelClose);
            self.window_open_list.root = Some(RootSave::default());
        }

        if let Some(display) = self.window_open_list.root.as_mut().and_then(|root_save| root_save.display(ctx)) {
            match display {
                RootSaveType::Cancel => {
                    self.window_open_list.root = None;
                }
                RootSaveType::SaveOnExit => {
                    let result = self.save_data_base();
                    let error_message = &mut self.window_open_list.root.as_mut().unwrap().error_message;
                    if let Err(_) = result {
                         *error_message = "failed save".to_string();
                    } else {
                        *error_message = "saved".to_string();
                        ctx.send_viewport_cmd_to(ViewportId::ROOT, ViewportCommand::Close);
                    }
                }
                RootSaveType::NotingSave => {
                    mark_as_graceful_exited_to_file().unwrap();
                    ctx.send_viewport_cmd_to(ViewportId::ROOT, ViewportCommand::Close);
                }
            }
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
