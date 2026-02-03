use team5::master_secrets::__manual_zeroize;
use std::io;
use std::io::{stdin, Write};
use std::process::exit;
use log::error;
use single_instance::SingleInstance;
use team5::data_base::{add_user_pw, change_user_pw, get_password, prefix_range, remove_user_pw, zeroize_db, SiteName, UserID, UserPW, DB};

fn main() {
    // let instance = SingleInstance::new("team-5").unwrap();
    // if size_of::<usize>() != 64 { error!("Unsupported Architecture") };
    //
    // if !instance.is_single() {
    //     // error!("This instance is not a single.");
    //     // return Ok(());
    // }

    without_gui();
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
    use sha2::{Digest, Sha256};
    use sha2::digest::FixedOutputReset;
    use sha2::digest::generic_array::GenericArray;
    use zeroize::{Zeroize, Zeroizing};
    use team5::master_secrets::{__manual_zeroize, change_master_pw, decrypt_db, encrypt_db, get_master_pw_hash, set_master_pw_and_1st_login};
    use team5::data_base::{add_user_pw, change_user_pw, explor_db, get_password, prefix_range, remove_user_pw, zeroize_db, DBIOError, SiteName, UserID, UserPW, DB};
    use team5::file_io::{load_db, mark_as_graceful_exited_to_file, mark_as_ungraceful_exited_to_file, save_db, FileIOWarn};
    use team5::header::Salt;
    use team5::manual_zeroize;
    use team5::master_secrets::{check_master_pw_and_login, EciesKeyPair};
    use team5::master_secrets::master_pw::MasterPW;
    use team5::user_secrets::{get_system_identity, UserKey, WrappedUserKey};

    use super::*;

    // #[test]

}


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
        println!("[ First Login ]");
        loop {
            print!("Please enter new master password: ");
            io::stdout().flush().unwrap();
            let mut raw_master_pw = Zeroizing::new(String::new());
            stdin().read_line(&mut raw_master_pw).unwrap();
            let mut master_pw = match MasterPW::new(raw_master_pw) {
                Ok(v) => v,
                Err(err) => {
                    println!("MasterPW creation error: {}", err);
                    continue;
                }
            };
            let master_pw_hash = get_master_pw_hash(&master_pw);
            master_pw.zeroize();
            print!("Please confirm master password: ");
            io::stdout().flush().unwrap();
            let mut raw_master_pw_confirm = Zeroizing::new(String::new());
            stdin().read_line(&mut raw_master_pw_confirm).unwrap();
            let mut master_pw_confirm = MasterPW::from_unchecked(raw_master_pw_confirm);
            let master_pw_confirm_hash = get_master_pw_hash(&master_pw_confirm);
            if master_pw_hash != master_pw_confirm_hash {
                println!("password is missmatch");
                master_pw_confirm.zeroize();
                continue;
            }
            (ecies_keys, db_header.db_salt, wrapped_user_key) = match set_master_pw_and_1st_login(master_pw_confirm) {
                Ok(v) => v,
                Err(e) => {
                    println!("Error setting master pw: {}", e);
                    continue;
                }
            };
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
        println!("[ General Login ]");
        loop {
            print!("Please enter master password: ");
            io::stdout().flush().unwrap();
            let mut raw_master_pw = Zeroizing::new(String::new());
            stdin().read_line(&mut raw_master_pw).unwrap();
            io::stdout().flush().unwrap();
            let mut master_pw = match MasterPW::new(raw_master_pw) {
                Ok(v) => v,
                Err(e) => {
                    println!("MasterPW checking master pw: {}", e);
                    continue;
                }
            };
            (ecies_keys, wrapped_user_key) = match check_master_pw_and_login(master_pw, db_header.db_salt.clone()) {
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
        let args = std::iter::once(">").chain(words);
        match UserRequest::try_parse_from(args) {
            Ok(request) =>
                match request {
                    UserRequest::AddUserPW { site, id, pw } => {
                        if let Err(e) = add_user_pw(&mut db, site, id, pw, &wrapped_user_key) {
                            println!("Error adding password: {}", e);
                            continue
                        }
                        if let Err(err) = mark_as_ungraceful_exited_to_file() {
                            println!("Error saving status: {}", err);
                            continue;
                        }
                    }
                    UserRequest::ChangeUserPW { site, id, pw } => {
                        if let Err(e) = change_user_pw(&mut db, site, id, pw, &wrapped_user_key) {
                            println!("Error changing password: {}", e);
                            continue;
                        }
                        if let Err(err) = mark_as_ungraceful_exited_to_file() {
                            println!("Error saving status: {}", err);
                            continue;
                        }
                    }
                    UserRequest::RemoveUserPW { site, id } => {
                        if let Err(e) = remove_user_pw(&mut db, site, id) {
                            println!("Error removing password: {}", e);
                            continue;
                        }
                        if let Err(err) = mark_as_ungraceful_exited_to_file() {
                            println!("Error saving status: {}", err);
                            continue;
                        }
                    }
                    UserRequest::GetUserPW { site, id } => {
                        let pw = match get_password(&mut db, &site, &id, &wrapped_user_key) {
                            Ok(v) => {v}
                            Err(e) => {
                                println!("Error getting password: {}", e);
                                continue;
                            }
                        };
                        println!("{}", pw.as_str());
                    }
                    UserRequest::PrefixSearch { site } => {
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
                    UserRequest::ChangeMasterPW => {
                        print!("Please enter new master password: ");
                        io::stdout().flush().unwrap();
                        let mut raw_master_pw = Zeroizing::new(String::new());
                        stdin().read_line(&mut raw_master_pw).unwrap();
                        let mut master_pw = match MasterPW::new(raw_master_pw) {
                            Ok(v) => v,
                            Err(err) => {
                                println!("MasterPW creation error: {}", err);
                                continue;
                            }
                        };
                        let master_pw_hash = get_master_pw_hash(&master_pw);
                        master_pw.zeroize();
                        print!("Please confirm master password: ");
                        io::stdout().flush().unwrap();
                        let mut raw_master_pw_confirm = Zeroizing::new(String::new());
                        stdin().read_line(&mut raw_master_pw_confirm).unwrap();
                        let mut master_pw_confirm = MasterPW::from_unchecked(raw_master_pw_confirm);
                        let master_pw_confirm_hash = get_master_pw_hash(&master_pw_confirm);
                        if master_pw_hash != master_pw_confirm_hash {
                            println!("password is missmatch");
                            master_pw_confirm.zeroize();
                            continue;
                        }
                        (ecies_keys.pk, db_header.db_salt, wrapped_user_key) = match change_master_pw(&mut db, master_pw_confirm, wrapped_user_key.clone()) {
                            Ok(v) => v,
                            Err(e) => {
                                println!("Error setting master pw: {}", e);
                                continue;
                            }
                        };

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
                    }
                    UserRequest::SaveDB => {
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
                    UserRequest::ExitAppWithSave => {
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
                        exit(0);
                    }
                    UserRequest::ExitAppWithoutSave => {
                        // if !should_save_db {
                        mark_as_graceful_exited_to_file().ok();
                        // }
                        manual_zeroize!(wrapped_user_key);
                        manual_zeroize!(ecies_keys.pk);
                        zeroize_db(&mut db);
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


use clap::{Error, Parser};
use zeroize::{Zeroize, Zeroizing};
use team5::file_io::{load_db, mark_as_graceful_exited_to_file, mark_as_ungraceful_exited_to_file, save_db};
use team5::manual_zeroize;
use team5::master_secrets::{change_master_pw, check_master_pw_and_login, decrypt_db, encrypt_db, get_master_pw_hash, set_master_pw_and_1st_login};
use team5::master_secrets::master_pw::MasterPW;
use team5::user_secrets::get_system_identity;
use crate::UserRequest::ExitAppWithoutSave;

#[derive(Parser)]
pub enum UserRequest {
    AddUserPW {site: SiteName, id: UserID, pw: UserPW},
    ChangeUserPW {site: SiteName, id: UserID, pw: UserPW},
    RemoveUserPW {site: SiteName, id: UserID},
    GetUserPW {site: SiteName, id: UserID},
    PrefixSearch {site: String},
    ChangeMasterPW,
    SaveDB,
    ExitAppWithSave,
    ExitAppWithoutSave,
}