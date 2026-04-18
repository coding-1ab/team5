use std::fs;
use anyhow::{anyhow, Error};
use eframe::egui::{
    self,
    ViewportBuilder,
    ViewportCommand,
    ViewportId,
    Key,
    Pos2,
    TextEdit,
    Ui,
    Vec2
};
use zeroize::Zeroize;
use engine::{
    data_base::{add_user_pw, change_user_pw, remove_user_pw, SiteName, UserID, UserPW, DB},
    file_io::{check_can_directly_exit, mark_as_ungraceful_exited_to_file, save_db, DB_BAK_FILE, DB_FILE},
    header::{DBHeader, Salt},
    master_secrets::{decrypt_db, encrypt_db, general_login, master_pw_validation, EncryptedDB},
    x25519::PubKey,
    file_io::mark_as_graceful_exited_to_file,
    master_secrets::{change_master_pw, first_login}
};
use crate::{
    command_builder::CommandBuilder,
    graphical_user_interface::KeyPair
};

pub enum RootSaveType {
    Cancel,
    SaveOnExit,
    DontSave
}

#[derive(Default)]
pub struct ExistingUser {
    password: String,
    error_message: String,
    reset: Option<Reset>,
    loading: bool
}

impl ExistingUser {
    pub fn display(
        &mut self,
        ui: &Ui,
        encrypted_data_base: &EncryptedDB,
        root_window: &mut Option<RootSave>,
        master_password_salt: &Salt,
        data_base: &mut DB,
        graphical_user_interface_public_key: &mut Option<PubKey>,
        key: &mut Option<KeyPair>,
        login: &mut bool,
        warning_message: &String,
        #[cfg(target_os = "windows")]
        center: [i32; 2]
    ) -> bool {
        let mut keep = true;

        let size = [300.0, 175.0];

        let mut viewport_builder = ViewportBuilder::default().with_title("마스터 로그인")
            .with_inner_size(size);

        #[cfg(target_os = "windows")]
        {
            let pixels_per_point = ui.native_pixels_per_point().unwrap_or(ui.pixels_per_point());
            let egui_center = [center[0] as f32 / pixels_per_point - size[0] / 2.0, center[1] as f32 / pixels_per_point - size[1] / 2.0];
            viewport_builder = viewport_builder.with_position(egui_center);
        }

        ui.show_viewport_immediate(
            ViewportId::from_hash_of("master_login"),
            viewport_builder,
            |ui, _| {
                if ui.input(|i| i.viewport().close_requested()) {
                    exit_root(ui, root_window);
                }
                egui::CentralPanel::default().show_inside(ui, |ui| {
                    ui.label("input master password");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.password)
                            .password(true),
                    );
                    ui.label(&self.error_message);
                    let login_button = ui.button("login");
                    if self.loading {
                        self.loading = false;

                        let result = || -> Result<(DB, PubKey, KeyPair), Error> {
                            if let Err(error) = master_pw_validation(&self.password) {
                                return Err(error.into());
                            }

                            let (secret_key, public_key, wrapped_session_key, session_key_nonce) =
                                general_login(&mut self.password, master_password_salt);

                            self.password.zeroize();
                            match decrypt_db(encrypted_data_base, secret_key) {
                                Ok(decrypted_data_base) => Ok((decrypted_data_base, public_key, (wrapped_session_key, session_key_nonce))),
                                Err(error) => { Err(error.into()) }
                            }
                        }();

                        match result {
                            Ok((decrypted_data_base, public_key, key_pair)) => {
                                *data_base = decrypted_data_base;
                                *graphical_user_interface_public_key = Some(public_key);
                                *key = Some(key_pair);

                                *login = true;
                                keep = false;
                            }
                            Err(error) => {
                                self.password.zeroize();
                                self.error_message = error.to_string();
                            }
                        }
                    }
                    if ui.button("reset").clicked() {
                        self.reset = Some(Reset::default());
                    }
                    if let Some(reset) = &mut self.reset {
                        if !reset.display(ui) {
                            self.reset = None;
                        }
                    }
                    ui.label(warning_message);
                    if login_button.clicked() || ui.input(|input_state| input_state.key_pressed(Key::Enter)) {
                        ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
                            ui.label("loading");
                        });
                        self.loading = true;
                        return;
                    }
                });
            },
        );

        keep
    }
}

#[derive(Default)]
pub struct FirstLogin {
    password: String,
    recheck_password: String,
    error_message: String,
    loading: bool,
}

impl FirstLogin {
    pub fn display(
        &mut self,
        ui: &Ui,
        data_base_header: &mut DBHeader,
        key: &mut Option<KeyPair>,
        data_base: &mut DB,
        graphical_user_interface_public_key: &mut Option<PubKey>,
        login: &mut bool,
        root_window: &mut Option<RootSave>,
        warning_message: &String,
        #[cfg(target_os = "windows")]
        center: [i32; 2]
    ) -> bool {
        let mut keep = true;

        let size = [300.0, 175.0];

        let mut viewport_builder = ViewportBuilder::default().with_title("첫 마스터 로그인")
            .with_inner_size(size);

        #[cfg(target_os = "windows")]
        {
            let center = [center[0] as f32 - size[0] / 2.0, center[1] as f32 - size[1] / 2.0];
            viewport_builder = viewport_builder.with_position(center);
        }

        ui.show_viewport_immediate(
            ViewportId::from_hash_of("first_master_login"),
            viewport_builder,
            |ui, _| {
                if ui.input(|input_state| input_state.viewport().close_requested()) {
                    exit_root(ui, root_window);
                    return;
                }
                egui::CentralPanel::default().show_inside(ui, |ui| {
                    ui.label("input new master password");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.password)
                            .password(true),
                    );
                    ui.label("recheck master password");
                    ui.add(
                        egui::TextEdit::singleline(
                            &mut self.recheck_password,
                        )
                            .password(true),
                    );
                    ui.label(&self.error_message);
                    let sign_in_button = ui.button("sign in");
                    if self.loading {
                        self.loading = false;
                        if let Err(err) =
                            master_pw_validation(&self.password)
                        {
                            self.error_message =
                                format!("Master password validation error: {}", err);
                            self.password.zeroize();
                            self.recheck_password.zeroize();
                            return;
                        }
                        if self.password
                            == self.recheck_password
                        {
                            let (
                                public_key,
                                data_base_header_salt,
                                wrapped_session_key,
                                session_key_nonce,
                            ) = first_login(&mut self.password);
                            self.password.zeroize();
                            self.recheck_password.zeroize();
                            data_base_header.master_pw_salt = data_base_header_salt;
                            *key = Some((wrapped_session_key, session_key_nonce));
                            *data_base = DB::default();
                            save_db(
                                data_base_header,
                                encrypt_db(data_base, &public_key),
                            )
                                .expect("unreachable");
                            *graphical_user_interface_public_key = Some(public_key);
                            *login = true;
                            keep = false;
                        } else {
                            self.password.zeroize();
                            self.recheck_password.zeroize();
                            self.error_message =
                                "password is mismatch".to_string();
                            return;
                        }
                    }
                    if sign_in_button.clicked() || ui.input(|input_state| input_state.key_pressed(Key::Enter)) {
                        ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
                            ui.label("loading");
                        });
                        self.loading = true;
                    }
                    ui.label(warning_message);
                });
            },
        );

        keep
    }
}

#[derive(Default)]
struct Reset {
    reset_error: String,
}

impl Reset {
    pub fn display(&mut self, ui: &Ui) -> bool {
        let mut keep = true;

        egui::Window::new("reset").resizable([false, false]).interactable(false).show(ui, |ui| {
            egui::CentralPanel::default().show_inside(ui, |ui| {
                ui.label("리셋하겠습니까? 복구할 수 없습니다.");
                ui.horizontal(|ui| {
                    if ui.button("submit").clicked() {
                        match fs::remove_file(DB_FILE)
                            .and_then(|_| fs::remove_file(DB_BAK_FILE))
                        {
                            Ok(_) => keep = false,
                            Err(error) => {
                                self.reset_error = error.to_string();
                            }
                        }
                    }
                    if ui.button("cancel").clicked() {
                        keep = false;
                    }
                    ui.label(&self.reset_error);
                    })
                })
            },
        );

        keep
    }
}

#[derive(Default)]
pub struct RootSave {
    pub error_message: String,
}

impl RootSave {
    pub fn display(&mut self, ui: &Ui, #[cfg(target_os = "windows")] center: [i32; 2]) -> Option<RootSaveType> {
        let mut root_save_type = None;

        let size = [250.0, 50.0];

        let mut viewport_builder = ViewportBuilder::default().with_title("close")
            .with_inner_size(size);

        #[cfg(target_os = "windows")]
        {
            let center = [center[0] as f32 - size[0] / 2.0, center[1] as f32 - size[1] / 2.0];
            viewport_builder = viewport_builder.with_position(center);
        }

        ui.show_viewport_immediate(
            ViewportId::from_hash_of("close"),
            viewport_builder,
            |ui, _| {
                if ui.input(|input_state| input_state.viewport().close_requested()) {
                    root_save_type = Some(RootSaveType::Cancel);
                    return;
                }

                egui::CentralPanel::default().show_inside(ui, |ui| {
                    ui.horizontal(|ui| {
                        if ui.button("cancel").clicked() {
                            root_save_type = Some(RootSaveType::Cancel);
                        }
                        if ui.button("save on exit").clicked() {
                            root_save_type = Some(RootSaveType::SaveOnExit);
                        }
                        if ui.button("don't save").clicked() {
                            root_save_type = Some(RootSaveType::DontSave);
                        }
                    });
                    ui.label(&self.error_message);
                });
            },
        );

        root_save_type
    }
}

#[derive(Default)]
pub struct AddUserPassword {
    site_name: String,
    identifier: String,
    password: String,
    error_message: String,
}

impl AddUserPassword {
    pub fn display(&mut self, ui: &Ui, key: &KeyPair, data_base: &mut DB, #[cfg(target_os = "windows")] center: [i32; 2]) -> bool {
        CommandBuilder::new("add user password", "add user password", None, #[cfg(target_os = "windows")] center)
            .input("site name", &mut self.site_name)
            .input("user identifier", &mut self.identifier)
            .sensitive_input("password", &mut self.password)
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
            .error_message(&mut self.error_message)
            .show(ui)
    }
}

#[derive(Default)]
pub struct ChangeUserPassword {
    site_name: String,
    identifier: String,
    password: String,
    error_message: String,
}

impl ChangeUserPassword {
    pub fn display(&mut self, ui: &Ui, key: &KeyPair, data_base: &mut DB, #[cfg(target_os = "windows")] center: [i32; 2]) -> bool {
        CommandBuilder::new("change user password", "change user password", None, #[cfg(target_os = "windows")] center)
            .input("site name", &mut self.site_name)
            .input("user identifier", &mut self.identifier)
            .sensitive_input("password", &mut self.password)
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
            .error_message(&mut self.error_message)
            .show(ui)
    }
}

#[derive(Default)]
pub struct RemoveUserPassword {
    site_name: String,
    identifier: String,
    error_message: String,
}

impl RemoveUserPassword {
    pub fn display(&mut self, ui: &Ui, data_base: &mut DB, #[cfg(target_os = "windows")] center: [i32; 2]) -> bool {
        CommandBuilder::new("remove user password", "remove user password", None, #[cfg(target_os = "windows")] center)
            .input("site name", &mut self.site_name)
            .input("user identifier", &mut self.identifier)
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
            .error_message(&mut self.error_message)
            .show(ui)
    }
}

#[derive(Default)]
pub struct AddUserPasswordWithSiteName {
    user_identifier: String,
    password: String,
    error_message: String,
}

impl AddUserPasswordWithSiteName {
    pub fn display(&mut self, ui: &Ui, key: &KeyPair, data_base: &mut DB, site_name: &SiteName, #[cfg(target_os = "windows")] center: [i32; 2]) -> bool {
        CommandBuilder::new("add user password with", "add user password with", None, #[cfg(target_os = "windows")] center)
            .input("user identifier", &mut self.user_identifier)
            .sensitive_input("password", &mut self.password)
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
            .error_message(&mut self.error_message)
            .show(ui)
    }
}

#[derive(Default)]
pub struct ChangeUserPasswordWithSiteName {
    user_identifier: String,
    password: String,
    error_message: String,
}

impl ChangeUserPasswordWithSiteName {
    pub fn display(&mut self, ui: &Ui, key: &KeyPair, data_base: &mut DB, site_name: &SiteName, #[cfg(target_os = "windows")] center: [i32; 2]) -> bool {
        CommandBuilder::new("change user password", "change user password", None, #[cfg(target_os = "windows")] center)
            .input("user identifier", &mut self.user_identifier)
            .sensitive_input("password", &mut self.password)
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
            .error_message(&mut self.error_message)
            .show(ui)
    }
}

#[derive(Default)]
pub struct RemoveUserPasswordWithSiteName {
    user_identifier: String,
    error_message: String,
}

impl RemoveUserPasswordWithSiteName {
    pub fn display(&mut self, ui: &Ui, data_base: &mut DB, site_name: &SiteName, #[cfg(target_os = "windows")] center: [i32; 2]) -> bool {
        CommandBuilder::new("remove user password", "remove user password", None, #[cfg(target_os = "windows")] center)
            .input("user identifier", &mut self.user_identifier)
            .set_database(data_base)
            .execute(|inputs, data_base, _, _| {
                let user_identifier = UserID::new(inputs[0].value)?;
                remove_user_pw(data_base.expect("unreachable"), site_name, &user_identifier)?;
                mark_as_ungraceful_exited_to_file()?;
                Ok(())
            })
            .on_success(|_| {})
            .error_message(&mut self.error_message)
            .show(ui)
    }
}

#[derive(Default)]
pub struct ChangeUserPasswordWithSiteNameWithUserIdentifier {
    password: String,
    error_message: String,
}

impl ChangeUserPasswordWithSiteNameWithUserIdentifier {
    pub fn display(&mut self, ui: &Ui, key: &KeyPair, data_base: &mut DB, site_name: &SiteName, user_identifier: &UserID, #[cfg(target_os = "windows")] center: [i32; 2]) -> bool {
        CommandBuilder::new("change user password", "change user password", None, #[cfg(target_os = "windows")] center)
            .sensitive_input("password", &mut self.password)
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
            .error_message(&mut self.error_message)
            .show(ui)
    }
}

#[derive(Default)]
pub struct RemoveUserPasswordWithSiteNameWithUserIdentifier {
    error_message: String,
}

impl RemoveUserPasswordWithSiteNameWithUserIdentifier {
    pub fn display(&mut self, ui: &Ui, data_base: &mut DB, site_name: &SiteName, user_identifier: &UserID, #[cfg(target_os = "windows")] center: [i32; 2]) -> bool {
        CommandBuilder::new("remove user password", "remove user password", None, #[cfg(target_os = "windows")] center)
            .set_database(data_base)
            .execute(|_, data_base, _, _| {
                remove_user_pw(data_base.expect("unreachable"), site_name, user_identifier)?;
                mark_as_ungraceful_exited_to_file()?;
                Ok(())
            })
            .on_success(|_| {})
            .error_message(&mut self.error_message)
            .show(ui)
    }
}

#[derive(Default)]
pub struct ChangeMasterPassword {
    password: String,
    error_message: String,
    loading: bool,
}

impl ChangeMasterPassword {
    pub fn display(
        &mut self,
        ui: &Ui,
        data_base: &mut DB,
        key: &mut KeyPair,
        data_base_header: &mut DBHeader,
        graphical_user_interface_public_key: &mut Option<PubKey>
    ) -> bool {
        let mut keep_open = true;

        egui::Window::new("change master password").show(ui, |ui| {
                if ui.input(|i| i.viewport().close_requested()) {
                    keep_open = false;
                    return;
                }

                egui::CentralPanel::default().show_inside(ui, |ui| {
                    ui.label("change master password");

                    ui.horizontal(|ui| {
                        ui.label("master password");
                        ui.add(TextEdit::singleline(&mut self.password).password(true));
                    });

                    ui.label(&*self.error_message);

                    let submit_button = ui.button("submit");

                    if self.loading {
                        self.loading = false;

                        // validation
                        if self.password.trim().is_empty() {
                            self.error_message = "모든 필드를 입력해주세요!".to_string();
                            return;
                        }

                        // execute
                        let result = (|| -> Result<(), Error> {
                            if let Err(error) = master_pw_validation(&self.password) {
                                return Err(error.into());
                            }
                            let (wrapped_session_key, session_key_nonce) = key;
                            let (public_key, salt) = change_master_pw(
                                data_base,
                                &mut self.password,
                                wrapped_session_key,
                                session_key_nonce,
                            )?;

                            data_base_header.master_pw_salt = salt;
                            *graphical_user_interface_public_key = Some(public_key);

                            save_db(
                                data_base_header,
                                encrypt_db(
                                    data_base,
                                    graphical_user_interface_public_key
                                        .as_ref()
                                        .expect("unreachable"),
                                ),
                            )?;
                            mark_as_graceful_exited_to_file()?;
                            Ok(())
                        })();

                        // zeroize는 성공/실패 무관하게
                        self.password.zeroize();

                        match result {
                            Ok(_) => {
                                self.error_message.clear();
                                keep_open = false;
                            }
                            Err(err) => {
                                self.error_message = err.to_string();
                            }
                        }
                    }

                    if submit_button.clicked() || ui.input(|i| i.key_pressed(Key::Enter)) {
                        ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
                            ui.label("loading");
                        });
                        self.loading = true;
                    }
                });
            },
        );

        keep_open
    }
}

pub fn exit_root(ui: &Ui, root_window: &mut Option<RootSave>) {
    if check_can_directly_exit() {
        ui.send_viewport_cmd_to(ViewportId::ROOT, ViewportCommand::Close);
        return;
    }
    *root_window = Some(RootSave::default());
}

pub fn get_center<Size: Into<Vec2>, Pos: Into<Pos2>>(size: Size, center: Pos) -> Pos2 {
    let size = size.into();
    let center = center.into();

    egui::pos2(
        center.x - size.x * 0.5,
        center.y - size.y * 0.5,
    )
}