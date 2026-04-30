use std::{
    collections::{BTreeMap, HashMap},
    error::Error,
    fmt::Display,
    time::{Instant, Duration},
};
use eframe::egui::{self, Pos2, Ui, ViewportBuilder, ViewportCommand, ViewportId};
use eframe::wgpu::rwh::{HasDisplayHandle, HasRawWindowHandle, HasWindowHandle};
use zeroize::Zeroize;
use engine::{
    data_base::{DB, SiteName, UserID, get_user_pw, prefix_range},
    file_io::{FileIOError, load_db, mark_as_graceful_exited_to_file, save_db},
    header::DBHeader,
    master_secrets::encrypt_db,
    sodium::rust_wrappings::x25519::PubKey,
    user_secrets::{SessionKeyNonce, WrappedSessionKey},
};
use engine::file_io::check_can_directly_exit;
use crate::window::{
    exit_root,
    AddUserPassword,
    AddUserPasswordWithSiteName,
    ChangeMasterPassword,
    ChangeUserPassword,
    ChangeUserPasswordWithSiteName,
    ChangeUserPasswordWithSiteNameWithUserIdentifier,
    ExistingUser,
    FirstLogin,
    RemoveUserPassword,
    RemoveUserPasswordWithSiteName,
    RemoveUserPasswordWithSiteNameWithUserIdentifier,
    RootSave,
    RootSaveType,
};

pub type KeyPair = (WrappedSessionKey, SessionKeyNonce);

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
    root: Option<RootSave>,
    add_user_password: Option<AddUserPassword>,
    change_user_password: Option<ChangeUserPassword>,
    remove_user_password: Option<RemoveUserPassword>,
    change_master_password: Option<ChangeMasterPassword>,
    add_user_password_with_site_name: BTreeMap<SiteName, AddUserPasswordWithSiteName>,
    change_user_password_with_site_name: BTreeMap<SiteName, ChangeUserPasswordWithSiteName>,
    remove_user_password_with_site_name: BTreeMap<SiteName, RemoveUserPasswordWithSiteName>,
    change_user_password_with_site_name_with_user_identifier:
    BTreeMap<SiteName, HashMap<UserID, ChangeUserPasswordWithSiteNameWithUserIdentifier>>,
    remove_user_password_with_site_name_with_user_identifier:
    BTreeMap<SiteName, HashMap<UserID, RemoveUserPasswordWithSiteNameWithUserIdentifier>>,
    existing_user: Option<ExistingUser>,
    first_login: Option<FirstLogin>,
    user_state: UserState,
}

#[derive(Default)]
struct MasterLogin {
    warning_message: String,
}

#[derive(Default)]
struct StringValues {
    search_data_base: String,
    save_data_base_label: String,
    master_login: MasterLogin,
}

#[derive(Default)]
pub struct GraphicalUserInterface {
    login: bool,
    loading: bool,
    not_first_frame: bool,
    string_values: StringValues,
    window_open_list: WindowOpenList,
    data_base: DB,
    data_base_header: DBHeader,
    key: Option<KeyPair>,
    public_key: Option<PubKey>,
    time: Option<Instant>,
    #[cfg(target_os = "windows")]
    pub center: [i32; 2],
}

impl GraphicalUserInterface {
    fn login(&mut self, ui: &Ui) {
        match load_db() {
            Ok((user_warning, data_base_header, encrypted_data_base)) => {
                self.data_base_header = data_base_header;
                if let Some(user_warning) = user_warning {
                    self.string_values.master_login.warning_message = user_warning.to_string();
                }
                match encrypted_data_base {
                    Some(encrypted_data_base) => {
                        if self.window_open_list.existing_user.is_none() {
                            self.window_open_list.existing_user = Some(ExistingUser::default())
                        }
                        if let Some(existing_user) = &mut self.window_open_list.existing_user {
                            if !existing_user.display(
                                ui,
                                &encrypted_data_base,
                                &mut self.window_open_list.root,
                                &self.data_base_header.master_pw_salt,
                                &mut self.data_base,
                                &mut self.public_key,
                                &mut self.key,
                                &mut self.login,
                                &self.string_values.master_login.warning_message,
                                #[cfg(target_os = "windows")]
                                self.center

                            ) {
                                self.window_open_list.existing_user = None;
                                return;
                            }
                        }
                    }
                    None => {
                        if self.window_open_list.first_login.is_none() {
                            self.window_open_list.first_login = Some(FirstLogin::default())
                        }
                        if let Some(first_login) = &mut self.window_open_list.first_login {
                            if !first_login.display(
                                ui,
                                &mut self.data_base_header,
                                &mut self.key,
                                &mut self.data_base,
                                &mut self.public_key,
                                &mut self.login,
                                &mut self.window_open_list.root,
                                &self.string_values.master_login.warning_message,
                                #[cfg(target_os = "windows")]
                                self.center
                            ) {
                                self.window_open_list.first_login = None;
                                return;
                            }
                        }
                    }
                }
            }
            Err(error) => {
                ui.show_viewport_immediate(
                    ViewportId::from_hash_of("master_login_err"),
                    ViewportBuilder::default()
                        .with_title("error")
                        .with_always_on_top()
                        .with_inner_size([350.0, 25.0])
                        .with_resizable(false)
                        .with_maximized(false)
                        .with_minimize_button(false),
                    |ui, _| {
                        if ui.input(|input_state| input_state.viewport().close_requested()) {
                            exit_root(ui, &mut self.window_open_list.root);
                            return;
                        }
                        egui::CentralPanel::default().show_inside(ui, |ui| {
                            ui.label(format!("Error loading db: {}", error));
                        });
                    },
                );
                return;
            }
        }
    }

    fn save_data_base(&mut self) -> Result<(), SaveError> {
        let encrypt_db = encrypt_db(
            &self.data_base,
            self.public_key.as_ref().ok_or(SaveError::NotingPublicKey)?,
        );
        save_db(&mut self.data_base_header, encrypt_db).map_err(SaveError::from)
    }

    fn user_main_view(&mut self, ui: &mut Ui) {
        egui::CentralPanel::default().show_inside(ui, |ui| {
            ui.horizontal(|ui| {
                let save_data_base = ui.button("save data base");
                if self.loading {
                    self.loading = false;
                    match self.save_data_base() {
                        Ok(()) => {
                            self.time = Some(Instant::now());
                            self.string_values.save_data_base_label = "saved data base".to_string();
                        }
                        Err(error) => {
                            self.string_values.save_data_base_label = error.to_string();
                        }
                    }
                }
                if save_data_base.clicked() {
                    ui.label("loading");
                    self.loading = true;
                    return;
                }
                ui.label(&self.string_values.save_data_base_label);
            });

            ui.horizontal(|ui| {

                if ui.button("add user password").on_hover_text("add user password").clicked() {
                    self.window_open_list.add_user_password = Some(AddUserPassword::default());
                }
                if let Some(add_user_password) = &mut self.window_open_list.add_user_password {
                    if !add_user_password.display(ui, self.key.as_ref().expect("unreachable"), &mut self.data_base, #[cfg(target_os = "windows")] self.center) {
                        self.window_open_list.add_user_password = None;
                    }
                }
                if ui.button("change user password").on_hover_text("change user password").clicked() {
                    self.window_open_list.change_user_password = Some(ChangeUserPassword::default());
                }
                if let Some(change_user_password) = &mut self.window_open_list.change_user_password {
                    if !change_user_password.display(ui, self.key.as_ref().expect("unreachable"), &mut self.data_base, #[cfg(target_os = "windows")] self.center) {
                        self.window_open_list.change_user_password = None;
                    }
                }
                if ui.button("remove user password").on_hover_text("remove user password").clicked() {
                    self.window_open_list.remove_user_password = Some(RemoveUserPassword::default());
                }
                if let Some(remove_user_password) = &mut self.window_open_list.remove_user_password {
                    if !remove_user_password.display(ui, &mut self.data_base, #[cfg(target_os = "windows")] self.center) {
                        self.window_open_list.remove_user_password = None;
                    }
                }
                if ui.button("change master password").on_hover_text("change master password").clicked() {
                    self.window_open_list.change_master_password = Some(ChangeMasterPassword::default())
                }
                if let Some(change_master_password) = &mut self.window_open_list.change_master_password {
                    if !change_master_password.display(ui, &mut self.data_base, self.key.as_mut().expect("unreachable"), &mut self.data_base_header, &mut self.public_key) {
                        self.window_open_list.change_master_password = None;
                    }
                }
            });
            ui.label("search");
            let response = ui.add(egui::TextEdit::singleline(
                &mut self.string_values.search_data_base,
            ));

            if !self.not_first_frame { response.request_focus() }

            self.not_first_frame = true;

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

            self.user_passwords_windows(ui);
        });
    }

    fn user_passwords_windows(&mut self, ui: &Ui) {
        let user_state = &mut self.window_open_list.user_state;
        let UserState {
            user_data,
            site_names,
        } = user_state;
        for (site_name, is_open) in site_names {
            if *is_open {
                ui.show_viewport_immediate(
                    ViewportId::from_hash_of(format!("{}_user_data", site_name.as_str())),
                    ViewportBuilder::default().with_title(format!("{} user data", site_name.as_str())),
                    |ui, _| {
                        if ui.input(|input_state| { input_state.viewport().close_requested() }) {
                            user_data.remove(site_name);
                            *is_open = false;
                        }

                        egui::CentralPanel::default().show_inside(ui, |ui| {
                            ui.label(site_name.as_str());
                            ui.horizontal(|ui| {
                                if ui.button("add user password").on_hover_text("add user password").clicked() {
                                    self.window_open_list.add_user_password_with_site_name.insert(site_name.clone(), AddUserPasswordWithSiteName::default());
                                }
                                if let Some(add_user_password_site_name) = self.window_open_list.add_user_password_with_site_name.get_mut(site_name) {
                                    if !add_user_password_site_name.display(ui, self.key.as_ref().unwrap(), &mut self.data_base, site_name, #[cfg(target_os = "windows")] self.center) {
                                        self.window_open_list.add_user_password_with_site_name.remove(site_name);
                                    }
                                }
                                if ui.button("change user password").on_hover_text("change user password").clicked() {
                                    self.window_open_list.change_user_password_with_site_name.insert(site_name.clone(), ChangeUserPasswordWithSiteName::default());
                                }
                                if let Some(change_user_password_with_site_name) = self.window_open_list.change_user_password_with_site_name.get_mut(site_name) {
                                    if !change_user_password_with_site_name.display(ui, self.key.as_ref().unwrap(), &mut self.data_base, site_name, #[cfg(target_os = "windows")] self.center) {
                                        self.window_open_list.change_user_password_with_site_name.remove(site_name);
                                    }
                                }
                                if ui.button("remove user password").on_hover_text("remove user password").clicked() {
                                    self.window_open_list.remove_user_password_with_site_name.insert(site_name.clone(), RemoveUserPasswordWithSiteName::default());
                                }
                                if let Some(remove_user_password_with_site_name) = self.window_open_list.remove_user_password_with_site_name.get_mut(site_name) {
                                    if !remove_user_password_with_site_name.display(ui, &mut self.data_base, site_name, #[cfg(target_os = "windows")] self.center) {
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
                                                if !change_user_password_with_size_name_with_user_identifier.display(ui, self.key.as_ref().unwrap(), &mut self.data_base, site_name, &user_identifier, #[cfg(target_os = "windows")] self.center) {
                                                    self.window_open_list.change_user_password_with_site_name_with_user_identifier.entry(site_name.clone()).or_default().remove(&user_identifier);
                                                }
                                            }
                                            if ui.button("remove user password").clicked() {
                                                self.window_open_list.remove_user_password_with_site_name_with_user_identifier.entry(site_name.clone()).or_default().entry(user_identifier.clone()).or_default();
                                            }
                                            if let Some(remove_user_password_with_size_name_with_user_identifier) = self.window_open_list.remove_user_password_with_site_name_with_user_identifier.get_mut(site_name).and_then(|value| value.get_mut(&user_identifier)) {
                                                if !remove_user_password_with_size_name_with_user_identifier.display(ui, &mut self.data_base, site_name, &user_identifier, #[cfg(target_os = "windows")] self.center) {
                                                    self.window_open_list.remove_user_password_with_site_name_with_user_identifier.entry(site_name.clone()).or_default().remove(&user_identifier);
                                                }
                                            }
                                            let copy_password_button = ui.button("copy password");
                                            if copy_password_button.clicked() {
                                                let user_password = {
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
                                                ui.copy_text(user_password.as_str().to_string());
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
}

impl eframe::App for GraphicalUserInterface {
    fn ui(&mut self, ui: &mut Ui, _frame: &mut eframe::Frame) {
        if ui.input(|input| input.viewport().close_requested()) {
            if check_can_directly_exit() {
                ui.send_viewport_cmd_to(ViewportId::ROOT, ViewportCommand::Close);
            } else {
                ui.send_viewport_cmd_to(ViewportId::ROOT, ViewportCommand::CancelClose);
                self.window_open_list.root = Some(RootSave::default());
            }
        }

        if let Some(root_save) = self.window_open_list.root.as_mut() {
            match root_save.display(ui, #[cfg(target_os = "windows")] self.center) {
                Some(display) => {
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
                                ui.send_viewport_cmd_to(ViewportId::ROOT, ViewportCommand::Close);
                                return;
                            }
                        }
                        RootSaveType::DontSave => {
                            mark_as_graceful_exited_to_file().unwrap();
                            ui.send_viewport_cmd_to(ViewportId::ROOT, ViewportCommand::Close);
                            return;
                        }
                    }
                }
                None => { }
            }
        }

        if !self.login {
            self.login(ui);
            return;
        }

        if let Some(time) = self.time {
            if time.elapsed() > Duration::from_secs(1) {
                self.string_values.save_data_base_label = "".to_string();
            }
        }

        ui.add_enabled_ui(!self.window_open_list.root.is_some(), |ui| {
            ui.send_viewport_cmd(ViewportCommand::Visible(true));
            ui.send_viewport_cmd(ViewportCommand::Title("비밀번호 관리자".to_string()));
            ui.send_viewport_cmd(ViewportCommand::InnerSize([800.0, 600.0].into()));
            self.user_main_view(ui);
        });
    }
}



pub(crate) fn loading(ui: &Ui) {
    ui.show_viewport_immediate(
        ViewportId::from_hash_of("loading"),
        ViewportBuilder::default().with_title("loading"),
        |ctx, _| {
            egui::CentralPanel::default().show_inside(ctx, |ui| {
                ui.label("Loading...");
            });
        },
    )
}
