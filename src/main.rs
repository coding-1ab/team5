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
    use log::warn;
    // use eframe::egui::accesskit::Role::Marquee;
    // use eframe::egui::CursorIcon::Default;
    use rkyv::rancor::ResultExt;
    use zeroize::{Zeroize, Zeroizing};
    use team5::master_secrets::{_manual_zeroize, decrypt_db, encrypt_db, set_master_pw_and_1st_login};
    use team5::data_base::{add_password, change_password, explor_db, get_password, prefix_range, remove_password, zeroize_db, DBIOError, SiteName, UserID, UserPW, DB};
    use team5::file_io::{load_db, mark_as_graceful_exited_to_file, mark_as_ungraceful_exited_to_file, save_db, FileIOWarn};
    use team5::header::Salt;
    use team5::manual_zeroize;
    use team5::master_secrets::{check_master_pw_and_login, EciesKeyPair};
    use team5::user_secrets::{UserKey, WrappedUserKey};

    use super::*;

    // #[test]
    pub(crate) fn without_gui() -> () {
        let instance = SingleInstance::new("team-5").unwrap();
        assert_eq!(size_of::<usize>(), 8, "Unsupported Architecture");

        if !instance.is_single() {
            println!("This instance is not a single.");
            return ();
        }

        // let mut should_save_db = true;

        let (is_first_login, user_wran, mut db_header, encrypted_db)
            = match load_db() {
            Ok(v) => {v}
            Err(e) => {
                println!("Error loading db: {}", e);
                return;
            }
        };
        match user_wran {
            Some(w) => {
                println!("Warn loading db: {}", w)
            }
            None => {}
        }

        let mut db: DB;
        let mut ecies_keys;
        let mut wrapped_user_key;
        if is_first_login {
            loop {
                println!("[ First Login ]");
                print!("Please enter new master password: ");
                io::stdout().flush().unwrap();
                let mut raw_master_pw = String::new();
                stdin().read_line(&mut raw_master_pw).unwrap();
                let mut tmp = match set_master_pw_and_1st_login(raw_master_pw.clone()) {
                    Ok(v) => { v }
                    Err(e) => {
                        println!("Error setting master pw: {}", e);
                        continue;
                    }
                };
                print!("Please confirm master password: ");
                io::stdout().flush().unwrap();
                let mut master_pw_confirm = String::new();
                stdin().read_line(&mut master_pw_confirm).unwrap();
                if raw_master_pw != master_pw_confirm {
                    println!("password is missmatch");
                    tmp.zeroize();
                    continue;
                }
                (ecies_keys, db_header.db_salt, wrapped_user_key) = tmp;
                break;
            }
            manual_zeroize!(ecies_keys.sk);
            drop(ecies_keys.sk);
            db = DB::new();

            let encryted_db = match encrypt_db(&db, &ecies_keys.pk) {
                Ok(v) => { v }
                Err(e) => {
                    println!("Error encrypting db: {}", e);
                    exit(0);
                }
            };
            if let Err(e) = save_db(db_header, encryted_db) {
                println!("Error saving db: {}", e);
                exit(0);
            }
            if let Err(err) = mark_as_graceful_exited_to_file() {
                println!("Error saving db: {}", err);
                exit(0);
            }
        } else {
            loop {
                println!("[ General Login ]");
                print!("Please enter master password: ");
                io::stdout().flush().unwrap();
                let mut raw_master_pw = String::new();
                stdin().read_line(&mut raw_master_pw).unwrap();
                print!("\r\x1B[2K");
                io::stdout().flush().unwrap();
                (ecies_keys, wrapped_user_key) = match check_master_pw_and_login(raw_master_pw, db_header.db_salt.clone()) {
                    Ok(v) => { v }
                    Err(e) => {
                        println!("Error checking master pw: {}", e);
                        continue;
                    }
                };
                db = match decrypt_db(&encrypted_db.as_ref().unwrap(), ecies_keys.sk) {
                    Ok(v) => { v }
                    Err(e) => {
                        println!("Error decrypting db: {}", e);
                        continue;
                    }
                };
                drop(encrypted_db);
                break;
            }
        }

        // let mut previous_save_status = false;
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
                                println!("Error adding password: {}", e);
                                continue
                            }
                            if let Err(err) = mark_as_ungraceful_exited_to_file() {
                                println!("Error saving status: {}", err);
                                continue;
                            }
                        }
                        UserRequst::ChangeUserPW { site, id, pw } => {
                            if let Err(e) = change_password(&mut db, site, id, pw, &wrapped_user_key) {
                                println!("Error changing password: {}", e);
                                continue;
                            }
                            if let Err(err) = mark_as_ungraceful_exited_to_file() {
                                println!("Error saving status: {}", err);
                                continue;
                            }
                        }
                        UserRequst::RemoveUserPW { site, id } => {
                            if let Err(e) = remove_password(&mut db, site, id) {
                                println!("Error removing password: {}", e);
                                continue;
                            }
                            if let Err(err) = mark_as_ungraceful_exited_to_file() {
                                println!("Error saving status: {}", err);
                                continue;
                            }
                        }
                        UserRequst::GetUserPW { site, id } => {
                            let pw = match get_password(&mut db, &site, &id, &wrapped_user_key) {
                                Ok(v) => {v}
                                Err(e) => {
                                    println!("Error getting password: {}", e);
                                    continue;
                                }
                            };
                            println!("{}", pw.as_str());
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
                            // if should_save_db {
                                let encryted_db = match encrypt_db(&db, &ecies_keys.pk) {
                                    Ok(v) => { v }
                                    Err(e) => {
                                        println!("Error encrypting db: {}", e);
                                        continue;
                                    }
                                };
                                if let Err(e) = save_db(db_header, encryted_db) {
                                    println!("Error saving db: {}", e);
                                    continue;
                                }
                                if let Err(err) = mark_as_graceful_exited_to_file() {
                                    println!("Error saving db: {}", err);
                                    continue;
                                }
                            // }
                        }
                        UserRequst::ExitAppWithSave => {
                            // if should_save_db {
                                let encryted_db = match encrypt_db(&db, &ecies_keys.pk) {
                                    Ok(v) => { v }
                                    Err(e) => {
                                        println!("Error encrypting db: {}", e);
                                        continue;
                                    }
                                };
                                if let Err(e) = save_db(db_header, encryted_db) {
                                    println!("Error saving db: {}", e);
                                    continue;
                                }
                            // } else {
                            //     mark_as_graceful_exited_to_file().ok();
                            // }
                            manual_zeroize!(wrapped_user_key);
                            manual_zeroize!(ecies_keys.pk);
                            zeroize_db(&mut db);
                            drop(db);
                            exit(0);
                        }
                        UserRequst::ExitAppWithoutSave => {
                            // if !should_save_db {
                                mark_as_graceful_exited_to_file().ok();
                            // }
                            manual_zeroize!(wrapped_user_key);
                            manual_zeroize!(ecies_keys.pk);
                            zeroize_db(&mut db);
                            drop(db);
                            exit(0);
                        }
                    },

                Err(e) => {
                    println!("Invalid input: {}", e);
                }
            }
            // if !previous_save_status && should_save_db {
            //     if let Err(err) = mark_as_ungraceful_exited_to_file() {
            //         println!("Error saving status: {}", err);
            //         continue;
            //     }
            //     previous_save_status = should_save_db;
            // }
        }
    }
}


use clap::{Error, Parser};
use crate::UserRequst::ExitAppWithoutSave;

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