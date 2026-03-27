use anyhow::Error;
use eframe::{egui, egui::TextEdit};
use engine::data_base::UserID;
use engine::{
    data_base::{DB, SiteName},
    user_secrets::{SessionKeyNonce, WrappedSessionKey},
};
use std::collections::{BTreeMap, HashMap};
use zeroize::Zeroize;

// 하나의 입력 필드를 표현
pub struct InputField<'a> {
    pub label: &'static str,
    pub value: &'a mut String,
    pub want_zeroize: bool, // 에러 시 zeroize할지
}

// CommandBuilder 본체
pub struct CommandBuilder<'a, Output> {
    title: &'a str,
    screen_name: &'a str,
    inputs: Vec<InputField<'a>>,
    database: Option<&'a mut DB>,
    key: Option<&'a (WrappedSessionKey, SessionKeyNonce)>,
    key_mut: Option<&'a mut (WrappedSessionKey, SessionKeyNonce)>,
    on_success: Box<dyn FnMut(Output) + 'a>,
    // execute closure를 저장
    #[allow(clippy::complexity)]
    execute: Option<
        Box<
            dyn FnMut(
                    &mut Vec<InputField>,
                    Option<&mut DB>,
                    Option<&(WrappedSessionKey, SessionKeyNonce)>,
                    Option<&mut (WrappedSessionKey, SessionKeyNonce)>,
                ) -> Result<Output, Error>
                + 'a,
        >,
    >,
}

impl<'a, Output> CommandBuilder<'a, Output> {
    pub fn new(title: &'static str, screen_name: &'static str) -> Self {
        // command_fn은 이제 new()에서 안 받음
        Self {
            title,
            screen_name,
            inputs: Vec::new(),
            database: None,
            key: None,
            key_mut: None,
            on_success: Box::new(|_| {}),
            execute: None,
        }
    }

    // DB, Key는 여전히 선택적으로 설정
    pub fn set_database(mut self, db: &'a mut DB) -> Self {
        self.database = Some(db);
        self
    }

    pub fn set_key(mut self, key: &'a (WrappedSessionKey, SessionKeyNonce)) -> Self {
        self.key = Some(key);
        self
    }

    pub fn set_key_mut(mut self, key: &'a mut (WrappedSessionKey, SessionKeyNonce)) -> Self {
        self.key_mut = Some(key);
        self
    }

    // ← 여기서 핵심 변경
    pub fn execute<F>(mut self, execute_fn: F) -> Self
    where
        F: FnMut(
                &mut Vec<InputField>,
                Option<&mut DB>,
                Option<&(WrappedSessionKey, SessionKeyNonce)>,
                Option<&mut (WrappedSessionKey, SessionKeyNonce)>,
            ) -> Result<Output, Error>
            + 'a,
    {
        self.execute = Some(Box::new(execute_fn));
        self
    }

    pub fn input(mut self, label: &'static str, value: &'a mut String) -> Self {
        self.inputs.push(InputField {
            label,
            value,
            want_zeroize: false,
        });
        self
    }

    pub fn sensitive_input(mut self, label: &'static str, value: &'a mut String) -> Self {
        self.inputs.push(InputField {
            label,
            value,
            want_zeroize: true,
        });
        self
    }

    pub fn on_success<F>(mut self, callback: F) -> Self
    where
        F: FnMut(Output) + 'a,
    {
        self.on_success = Box::new(callback);
        self
    }

    pub fn error_message(
        self,
        error_message: &'a mut String,
    ) -> CommandBuilderWithError<'a, Output> {
        CommandBuilderWithError {
            inner: self,
            error_message,
        }
    }
}

// 중간 Builder (error_message가 설정된 상태)
pub struct CommandBuilderWithError<'a, Output> {
    inner: CommandBuilder<'a, Output>,
    error_message: &'a mut String,
}

impl<'a, Output> CommandBuilderWithError<'a, Output> {
    pub fn show(mut self, context: &egui::Context, button: egui::Response, window_open: &mut bool) {
        if button.clicked() {
            *window_open = true;
        }

        if !*window_open {
            return;
        }

        let error_message = &mut *self.error_message; // mutable borrow

        context.show_viewport_immediate(
            egui::ViewportId::from_hash_of(self.inner.title),
            egui::ViewportBuilder::default().with_title(self.inner.title),
            move |ctx, _| {
                if ctx.input(|i| i.viewport().close_requested()) {
                    *window_open = false;
                    return;
                }

                egui::CentralPanel::default().show(ctx, |ui| {
                    ui.label(self.inner.screen_name);

                    for field in &mut self.inner.inputs {
                        if !field.want_zeroize {
                            ui.horizontal(|ui| {
                                ui.label(field.label);
                                ui.text_edit_singleline(field.value);
                            });
                        } else {
                            ui.horizontal(|ui| {
                                ui.label(field.label);
                                ui.add(TextEdit::singleline(field.value).password(true));
                            });
                        }
                    }

                    ui.label(&*error_message);

                    if ui.button("submit").clicked()
                        || ctx.input(|input| input.key_pressed(egui::Key::Enter))
                    {
                        Self::handle_accept(&mut self.inner, error_message, window_open);
                    }
                });
            },
        );
    }

    fn handle_accept(
        builder: &mut CommandBuilder<'_, Output>,
        error_message: &mut String,
        window_open: &mut bool,
    ) {
        if builder.inputs.iter().any(|f| f.value.trim().is_empty()) {
            *error_message = "모든 필드를 입력해주세요!".to_string();
            return;
        }

        let values = &mut builder.inputs;

        match builder.execute.as_mut().unwrap()(
            values,
            builder.database.as_deref_mut(),
            builder.key,
            builder.key_mut.as_deref_mut(),
        ) {
            Ok(result) => {
                (builder.on_success)(result);
                *window_open = false;
                error_message.clear();
                for field in &mut builder.inputs {
                    if field.want_zeroize {
                        field.value.zeroize();
                    }
                }
            }
            Err(err) => {
                *error_message = err.to_string();

                // zeroize 처리
                for field in &mut builder.inputs {
                    if field.want_zeroize {
                        field.value.zeroize();
                    }
                }
            }
        }
    }
}

#[derive(Default)]
pub struct AddUserPassword {
    pub site_name: String,
    pub user_identifier: String,
    pub password: String,
    pub error_message: String,
}

#[derive(Default)]
pub struct ChangeUserPassword {
    pub site_name: String,
    pub user_identifier: String,
    pub password: String,
    pub error_message: String,
}

#[derive(Default)]
pub struct RemoveUserPassword {
    pub site_name: String,
    pub user_identifier: String,
    pub error_message: String,
}

#[derive(Default)]
pub struct ChangeMasterPassword {
    pub password: String,
    pub error_message: String,
}

#[derive(Default)]
pub struct AddUserPasswordWithSiteName {
    pub user_identifier: BTreeMap<SiteName, String>,
    pub password: BTreeMap<SiteName, String>,
    pub error_message: BTreeMap<SiteName, String>,
}

#[derive(Default)]
pub struct ChangeUserPasswordWithSiteName {
    pub user_identifier: BTreeMap<SiteName, String>,
    pub password: BTreeMap<SiteName, String>,
    pub error_message: BTreeMap<SiteName, String>,
}

#[derive(Default)]
pub struct RemoveUserPasswordWithSiteName {
    pub user_identifier: BTreeMap<SiteName, String>,
    pub error_message: BTreeMap<SiteName, String>,
}

#[derive(Default)]
pub struct ChangeUserPasswordWithSiteNameWithUserIdentifier {
    pub password: BTreeMap<SiteName, HashMap<UserID, String>>,
    pub error_message: BTreeMap<SiteName, HashMap<UserID, String>>,
}

#[derive(Default)]
pub struct RemoveUserPasswordWithSiteNameWithUserIdentifier {
    pub error_message: BTreeMap<SiteName, HashMap<UserID, String>>,
}

#[derive(Default)]
pub struct CommandValue {
    pub add_user_password: AddUserPassword,
    pub change_user_password: ChangeUserPassword,
    pub remove_user_password: RemoveUserPassword,
    pub change_master_password: ChangeMasterPassword,
    pub add_user_password_with_site_name: AddUserPasswordWithSiteName,
    pub change_user_password_with_site_name: ChangeUserPasswordWithSiteName,
    pub remove_user_password_with_site_name: RemoveUserPasswordWithSiteName,
    pub change_user_password_with_site_name_with_user_identifier:
        ChangeUserPasswordWithSiteNameWithUserIdentifier,
    pub remove_user_password_with_site_name_with_user_identifier:
        RemoveUserPasswordWithSiteNameWithUserIdentifier,
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
