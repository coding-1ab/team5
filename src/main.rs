use log::error;
use single_instance::SingleInstance;
use team5::data_base::{SiteName, UserID, UserPW};

fn main() {
    // let instance = SingleInstance::new("team-5").unwrap();
    // if size_of::<usize>() != 64 { error!("Unsupported Architecture") };
    //
    // if !instance.is_single() {
    //     // error!("This instance is not a single.");
    //     // return Ok(());
    // }
    tests::without_gui();
    // #[cfg(feature = "gui")]
    // {
    //     use team5::ui::graphical_user_interface::GraphicalUserInterface;
    //     let options = eframe::NativeOptions::default();
    //     eframe::run_native(
    //         "eframe example",
    //         options,
    //         Box::new(|_cc| Ok(Box::new(GraphicalUserInterface::default()))),
    //     ).unwrap()
    // }
}

// #[cfg(test)]
pub mod tests {
    use std::collections::{HashMap, VecDeque};
    use std::io;
    use std::io::{stdin, Write};
    use std::process::exit;
    use std::str::FromStr;
    // use eframe::egui::accesskit::Role::Marquee;
    // use eframe::egui::CursorIcon::Default;
    use rkyv::rancor::ResultExt;
    use zeroize::Zeroize;
    use team5::master_secrets::{_manual_zeroize, decrypt_db, encrypt_db, set_master_pw_and_1st_login};
    use team5::data_base::{add_password, change_password, explor_db, get_password, prefix_range, remove_password, zeroize_db, DBIOError, SiteName, UserID, UserPW, DB};
    use team5::file_io::{load_db, save_db, FileIOWarn};
    use team5::header::Salt;
    use team5::manual_zeroize;
    use team5::master_secrets::{check_master_pw_and_login, EciesKeyPair};
    use team5::user_secrets::{UserKey, WrappedUserKey};

    use super::*;

    // #[test]
    pub(crate) fn without_gui() -> () {
        let instance = SingleInstance::new("team-5").unwrap();
        if size_of::<usize>() != 64 { error!("Unsupported Architecture") };

        if !instance.is_single() {
            error!("This instance is not a single.");
            return ();
        }

        let (is_first_login, user_wran, mut db_header, encrypted_db)
            = match load_db() {
            Ok(v) => {v}
            Err(e) => {
                error!("Error loading db: {}", e);
                return;
            }
        };
        // user_warn 표시

        let mut db: DB;
        let mut ecies_keys;
        let mut ecies_key_salt= Salt::default();
        let mut wrapped_user_key;
        if is_first_login {
            loop {
                let raw_master_pw = String::from("12341234"); // 입력창 통해 마스터 비번 입력
                (ecies_keys, ecies_key_salt, wrapped_user_key) = match set_master_pw_and_1st_login(raw_master_pw) {
                    Ok(v) => {v}
                    Err(e) => {
                        error!("Error setting master pw: {}", e);
                        continue;
                    }
                };
                break;
            }
            db_header.db_salt = ecies_key_salt;
            manual_zeroize!(ecies_keys.sk);
            drop(ecies_keys.sk);
            db = DB::new();
        } else {
            loop {
                let raw_pw = String::from("12341234"); // 입력창 통해 마스터 비번 입력
                (ecies_keys, wrapped_user_key) = match check_master_pw_and_login(raw_pw, db_header.db_salt.clone()) {
                    Ok(v) => { v }
                    Err(e) => {
                        error!("Error checking master pw: {}", e);
                        continue;
                    }
                };
                db = match decrypt_db(&encrypted_db.as_ref().unwrap(), ecies_keys.sk) {
                    Ok(v) => { v }
                    Err(e) => {
                        error!("Error decrypting db: {}", e);
                        continue;
                    }
                };
                drop(encrypted_db);
                break;
            }
        }

        loop {
            print!("> ");
            io::stdout().flush().unwrap();
            let mut input = String::new();
            io::stdin().read_line(&mut input).unwrap();
            let words = input.split_whitespace();
            let args = std::iter::once("app_name").chain(words);
            match UserRequst::try_parse_from(args) {
                Ok(request) =>
                    match request {
                        UserRequst::AddUserPW { site, id, pw } => {
                            if let Err(e) = add_password(&mut db, site, id, pw, &wrapped_user_key) {
                                error!("Error adding password: {}", e);
                            } else { continue }
                            continue
                        }
                        UserRequst::ChangeUserPW { site, id, pw } => {
                            if let Err(e) = change_password(&mut db, site, id, pw, &wrapped_user_key) {
                                error!("Error changing password: {}", e);
                            }
                            continue;
                        }
                        UserRequst::RemoveUserPW { site, id } => {
                            if let Err(e) = remove_password(&mut db, site, id) {
                                error!("Error removing password: {}", e);
                            }
                            continue;
                        }
                        UserRequst::GetUserPW { site, id } => {
                            // match get_password(&mut db, &site, &id) {
                            //     Ok(v) => {v}
                            //     Err(e) => {
                            //         // error!("Error getting password: {}", e)
                            //         continue;
                            //     }
                            // }
                            println!("{}", get_password(&db, &site, &id, &wrapped_user_key).unwrap().as_str())
                        }
                        UserRequst::PrefixSearch { site } => {
                            // prefix_range(&db, site)
                            // continue;
                            // explor_db(&mut db, site, &wrapped_user_key);
                            for site in prefix_range(&db, &*site) {
                                println!("{}", site.0.as_str());
                                for user in site.1.iter() {
                                    println!("  {}", user.0.as_str());
                                }
                            }
                        }
                        UserRequst::SaveDB => {
                            let encryted_db = match encrypt_db(&db, &ecies_keys.pk) {
                                Ok(v) => { v }
                                Err(e) => {
                                    error!("Error encrypting db: {}", e);
                                    continue;
                                }
                            };
                            if let Err(e) = save_db(&mut db_header, encryted_db) {
                                error!("Error saving db: {}", e);
                                continue;
                            }
                            continue;
                        }
                        UserRequst::ExitAppWithSave => {
                            manual_zeroize!(ecies_key_salt, wrapped_user_key);
                            let encryted_db = match encrypt_db(&db, &ecies_keys.pk) {
                                Ok(v) => { v }
                                Err(e) => {
                                    error!("Error encrypting db: {}", e);
                                    continue;
                                }
                            };
                            manual_zeroize!(ecies_keys.pk);
                            if let Err(e) = save_db(&mut db_header, encryted_db) {
                                error!("Error saving db: {}", e);
                                continue;
                            }
                            zeroize_db(&mut db);
                            drop(db);
                            exit(0);
                        }
                        UserRequst::ExitAppWithoutSave => {
                            manual_zeroize!(ecies_key_salt, wrapped_user_key);
                            zeroize_db(&mut db);
                            drop(db);
                            exit(0);
                        }
                    },
                Err(e) => {
                    println!("Invalid input: {}", e);
                }
            }
        }
    }
}

use clap::{Error, Parser};
#[derive(Parser)]
pub enum UserRequst {
    AddUserPW{site: SiteName, id: UserID, pw: UserPW},
    ChangeUserPW{site: SiteName, id: UserID, pw: UserPW},
    RemoveUserPW{site: SiteName, id: UserID},
    GetUserPW{site: SiteName, id: UserID},
    PrefixSearch{site: String},
    SaveDB,
    ExitAppWithSave,
    ExitAppWithoutSave,
}