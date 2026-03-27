use anyhow::anyhow;
use eframe::egui;
use eframe::egui::{Context, ViewportBuilder, ViewportCommand, ViewportId};
use engine::data_base::{add_user_pw, change_user_pw, remove_user_pw, SiteName, UserID, UserPW, DB};
use engine::file_io::{mark_as_graceful_exited_to_file, mark_as_ungraceful_exited_to_file};
use engine::user_secrets::{SessionKey, SessionKeyNonce, WrappedSessionKey};
use crate::command_builder::CommandBuilder;
use crate::graphical_user_interface::GraphicalUserInterface;

pub enum RootSaveType {
    Cancel,
    SaveOnExit,
    NotingSave
}

#[derive(Default)]
pub struct RootSave {
    pub error_message: String,
}

impl RootSave {
    pub fn display(&mut self, context: &Context) -> Option<RootSaveType> {
        context.show_viewport_immediate(
            ViewportId::from_hash_of("close"),
            ViewportBuilder::default()
                .with_title("close")
                .with_inner_size([250.0, 50.0]),
            |ctx, _| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        if ui.button("cancel").clicked() {
                            return Some(RootSaveType::Cancel);
                        }
                        if ui.button("save on exit").clicked() {
                            return Some(RootSaveType::SaveOnExit);
                        }
                        if ui.button("noting save").clicked() {
                            return Some(RootSaveType::NotingSave);
                        }
                    });
                    ui.label(&self.error_message);
                });
            },
        );
        None
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
    pub fn display(&mut self, context: &Context, key: &(WrappedSessionKey, SessionKeyNonce), data_base: &mut DB) -> bool {
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
    pub fn display(&mut self, context: &Context, key: &(WrappedSessionKey, SessionKeyNonce), data_base: &mut DB) -> bool {
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
    pub fn display(&mut self, context: &Context, key: &(WrappedSessionKey, SessionKeyNonce), data_base: &mut DB) -> bool {
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
    pub fn display(&mut self, context: &Context, key: &(WrappedSessionKey, SessionKeyNonce), data_base: &mut DB, site_name: &SiteName) -> bool {
        CommandBuilder::new(&format!("add user password with {}", site_name.as_str()), &format!("add user password with {}", site_name.as_str()))
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
    pub fn display(&mut self, context: &Context, key: &(WrappedSessionKey, SessionKeyNonce), data_base: &mut DB, site_name: &SiteName) -> bool {
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
    pub fn display(&mut self, context: &Context, key: &(WrappedSessionKey, SessionKeyNonce), data_base: &mut DB, site_name: &SiteName, user_identifier: &UserID) -> bool {
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