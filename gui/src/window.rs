use std::fs;
use anyhow::anyhow;
use eframe::{
    egui,
    egui::{Context, ViewportBuilder, ViewportCommand, ViewportId}
};
use eframe::egui::TextBuffer;
use zeroize::Zeroize;
use engine::{
    data_base::{add_user_pw, change_user_pw, remove_user_pw, SiteName, UserID, UserPW, DB},
    file_io::{check_can_directly_exit, mark_as_ungraceful_exited_to_file, save_db, DB_BAK_FILE, DB_FILE},
    header::{DBHeader, Salt},
    master_secrets::{decrypt_db, encrypt_db, general_login, master_pw_validation, EncryptedDB},
    x25519::PubKey
};
use engine::file_io::mark_as_graceful_exited_to_file;
use engine::master_secrets::{change_master_pw, first_login};
use crate::{
    command_builder::CommandBuilder,
    graphical_user_interface::{loading, KeyPair}
};

pub enum RootSaveType {
    Cancel,
    SaveOnExit,
    NotingSave
}

#[derive(Default)]
pub struct ExistingUser {
    password: String,
    error_message: String,
    reset: Option<Reset>
}

impl ExistingUser {
    pub fn display(
        &mut self,
        context: &Context,
        encrypted_data_base: &EncryptedDB,
        root_window: &mut Option<RootSave>,
        master_password_salt: &Salt,
        data_base: &mut DB,
        graphical_user_interface_public_key: &mut Option<PubKey>,
        key: &mut Option<KeyPair>,
        login: &mut bool,
        warning_message: &String,
    ) -> bool {
        let mut keep = true;

        context.show_viewport_immediate(
            ViewportId::from_hash_of("master_login"),
            ViewportBuilder::default()
                .with_title("마스터 로그인")
                .with_inner_size([300.0, 175.0]),
            |ctx, _| {
                if ctx.input(|i| i.viewport().close_requested()) {
                    exit_root(context, root_window);
                }
                egui::CentralPanel::default().show(ctx, |ui| {
                    ui.label("input master password");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.password)
                            .password(true),
                    );
                    ui.label(&self.error_message);
                    if ui.button("login").clicked() {
                        loading(context);
                        if let Err(error) =
                            master_pw_validation(&self.password)
                        {
                            self.error_message = error.to_string();
                        }
                        let (secret_key, public_key, wrapped_session_key, session_key_nonce) =
                            general_login(
                                &mut self.password,
                                master_password_salt,
                            );
                        self.password.zeroize();
                        let decrypted_data_base = match decrypt_db(encrypted_data_base, secret_key)
                        {
                            Ok(decrypted_data_base) => decrypted_data_base,
                            Err(error) => {
                                self.error_message = error.to_string();
                                return;
                            }
                        };

                        *data_base = decrypted_data_base;
                        *graphical_user_interface_public_key = Some(public_key);
                        *key = Some((wrapped_session_key, session_key_nonce));

                        *login = true;
                        keep = false;
                    }
                    if ui.button("reset").clicked() {
                        self.reset = Some(Reset::default());
                    }
                    if let Some(reset) = &mut self.reset {
                        if !reset.display(context) {
                            self.reset = None;
                        }
                    }
                    ui.label(warning_message);
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
}

impl FirstLogin {
    pub fn display(
        &mut self,
        context: &Context,
        data_base_header: &mut DBHeader,
        key: &mut Option<KeyPair>,
        data_base: &mut DB,
        graphical_user_interface_public_key: &mut Option<PubKey>,
        login: &mut bool,
        root_window: &mut Option<RootSave>,
        warning_message: &String,
    ) -> bool {
        let mut keep = true;

        context.show_viewport_immediate(
            ViewportId::from_hash_of("first_master_login"),
            ViewportBuilder::default()
                .with_title("첫 마스터 로그인")
                .with_inner_size([300.0, 175.0]),
            |ctx, _| {
                if ctx.input(|input_state| input_state.viewport().close_requested()) {
                    exit_root(context, root_window);
                    return;
                }
                egui::CentralPanel::default().show(ctx, |ui| {
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
                    if ui.button("Accept").clicked() {
                        loading(context);
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
                            ) = first_login(self.password.take());
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
    pub fn display(&mut self, context: &Context) -> bool {
        let mut keep = true;

        context.show_viewport_immediate(
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
    pub fn display(&mut self, context: &Context) -> Option<RootSaveType> {
        let mut root_save_type = None;

        context.show_viewport_immediate(
            ViewportId::from_hash_of("close"),
            ViewportBuilder::default()
                .with_title("close")
                .with_inner_size([250.0, 50.0]),
            |ctx, _| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        if ui.button("cancel").clicked() {
                            root_save_type = Some(RootSaveType::Cancel);
                        }
                        if ui.button("save on exit").clicked() {
                            root_save_type = Some(RootSaveType::SaveOnExit);
                        }
                        if ui.button("noting save").clicked() {
                            root_save_type = Some(RootSaveType::NotingSave);
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
    pub fn display(&mut self, context: &Context, key: &KeyPair, data_base: &mut DB) -> bool {
        CommandBuilder::new("add user password", "add user password")
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
            .show(context)
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
    pub fn display(&mut self, context: &Context, key: &KeyPair, data_base: &mut DB) -> bool {
        CommandBuilder::new("change user password", "change user password")
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
            .show(context)
    }
}

#[derive(Default)]
pub struct RemoveUserPassword {
    site_name: String,
    identifier: String,
    error_message: String,
}

impl RemoveUserPassword {
    pub fn display(&mut self, context: &Context, key: &KeyPair, data_base: &mut DB) -> bool {
        CommandBuilder::new("remove user password", "remove user password")
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
            .show(context)
    }
}

#[derive(Default)]
pub struct AddUserPasswordWithSiteName {
    user_identifier: String,
    password: String,
    error_message: String,
}

impl AddUserPasswordWithSiteName {
    pub fn display(&mut self, context: &Context, key: &KeyPair, data_base: &mut DB, site_name: &SiteName) -> bool {
        CommandBuilder::new("add user password with", "add user password with")
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
            .show(context)
    }
}

#[derive(Default)]
pub struct ChangeUserPasswordWithSiteName {
    user_identifier: String,
    password: String,
    error_message: String,
}

impl ChangeUserPasswordWithSiteName {
    pub fn display(&mut self, context: &Context, key: &KeyPair, data_base: &mut DB, site_name: &SiteName) -> bool {
        CommandBuilder::new("change user password", "change user password")
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
            .show(context)
    }
}

#[derive(Default)]
pub struct RemoveUserPasswordWithSiteName {
    user_identifier: String,
    error_message: String,
}

impl RemoveUserPasswordWithSiteName {
    pub fn display(&mut self, context: &Context, data_base: &mut DB, site_name: &SiteName) -> bool {
        CommandBuilder::new("remove user password", "remove user password")
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
            .show(context)
    }
}

#[derive(Default)]
pub struct ChangeUserPasswordWithSiteNameWithUserIdentifier {
    password: String,
    error_message: String,
}

impl ChangeUserPasswordWithSiteNameWithUserIdentifier {
    pub fn display(&mut self, context: &Context, key: &KeyPair, data_base: &mut DB, site_name: &SiteName, user_identifier: &UserID) -> bool {
        CommandBuilder::new("change user password", "change user password")
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
            .show(context)
    }
}

#[derive(Default)]
pub struct RemoveUserPasswordWithSiteNameWithUserIdentifier {
    error_message: String,
}

impl RemoveUserPasswordWithSiteNameWithUserIdentifier {
    pub fn display(&mut self, context: &Context, data_base: &mut DB, site_name: &SiteName, user_identifier: &UserID) -> bool {
        CommandBuilder::new("remove user password", "remove user password")
            .set_database(data_base)
            .execute(|_, data_base, _, _| {
                remove_user_pw(data_base.expect("unreachable"), site_name, user_identifier)?;
                mark_as_ungraceful_exited_to_file()?;
                Ok(())
            })
            .on_success(|_| {})
            .error_message(&mut self.error_message)
            .show(context)
    }
}

#[derive(Default)]
pub struct ChangeMasterPassword {
    password: String,
    error_message: String,
}

impl ChangeMasterPassword {
    pub fn display(
        &mut self,
        context: &Context,
        data_base: &mut DB,
        key: &mut KeyPair,
        data_base_header: &mut DBHeader,
        graphical_user_interface_public_key: &mut Option<PubKey>
    ) -> bool {
        CommandBuilder::new("change master password", "change master password")
            .sensitive_input("master password", &mut self.password)
            .set_database(data_base)
            .set_key_mut(key)
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

                data_base_header.master_pw_salt = salt;
                *graphical_user_interface_public_key = Some(public_key);

                save_db(
                    data_base_header,
                    encrypt_db(data_base, graphical_user_interface_public_key.as_ref().expect("unreachable")),
                )?;
                mark_as_graceful_exited_to_file()?;
                Ok(())
            })
            .on_success(|_| {})
            .error_message(&mut self.error_message)
            .show(context)
    }
}


pub fn exit_root(context: &Context, root_window: &mut Option<RootSave>) {
    if check_can_directly_exit() {
        context.send_viewport_cmd_to(ViewportId::ROOT, ViewportCommand::Close)
    }
    *root_window = Some(RootSave::default());
}