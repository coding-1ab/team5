
use std::io;
use std::io::{stdin, Write};
use std::process::exit;
use single_instance::SingleInstance;
use zeroize::*;
use clap::*;
use zeroize::__internal::AssertZeroize;
use engine::data_base::*;
use engine::master_secrets::*;
use engine::file_io::*;
use engine::manual_zeroize;

pub fn cli_app() -> () {
    let instance = SingleInstance::new("team-5").unwrap();
    assert_eq!(size_of::<usize>(), 8, "Unsupported Architecture");

    if !instance.is_single() {
        println!("This instance is not a single.");
        return ();
    }

    // let mut should_save_db = true;

    let (user_wran, mut db_header, encrypted_db)
        = match load_db() {
            Ok(v) => {v}
            Err(e) => {
                println!("Error loading db: {}", e);
                exit(0);
        }
    };
    match user_wran {
        Some(w) => {
            println!("Warn loading db: {}", w)
        }
        None => {}
    }

    let mut db: DB;
    let mut pub_key;
    let mut wrapped_user_key;
    if encrypted_db.is_none() {
        println!("[ First Login ]");
        loop {
            print!("Please enter new master password: ");
            io::stdout().flush().unwrap();
            let mut master_pw = String::new();
            stdin().read_line(&mut master_pw).unwrap();
            if let Err(err) = master_pw_validation(&master_pw) {
                println!("MasterPW creation error: {}", err);
                master_pw.zeroize();
                continue;
            };
            print!("Please confirm master password: ");
            io::stdout().flush().unwrap();
            let mut master_pw_confirm = String::new();
            stdin().read_line(&mut master_pw_confirm).unwrap();
            let is_match = master_pw == master_pw_confirm;
            master_pw.zeroize();
            if !is_match {
                println!("password is missmatch");
                master_pw_confirm.zeroize();
                continue;
            }
            (pub_key, db_header.db_salt, wrapped_user_key) = first_login(master_pw_confirm);

            break;
        }

        db = DB::new();
        loop {
            let encrypted_db = encrypt_db(&db, &pub_key);
            if let Err(e) = save_db(db_header, encrypted_db) {
                println!("Error saving db: {}", e);
                println!("Please check your environment, and press <Enter> for try again");
                continue;
            }
            if let Err(err) = mark_as_graceful_exited_to_file() {
                println!("Error saving db: {}", err);
                println!("Please check your environment, and press <Enter> for try again");
                continue;
            }

            break;
        }
    } else {
        println!("[ General Login ]");
        loop {
            print!("Please enter master password: ");
            io::stdout().flush().unwrap();
            let mut master_pw = String::new();
            stdin().read_line(&mut master_pw).unwrap();
            io::stdout().flush().unwrap();
            if let Err(err) = master_pw_validation(&master_pw) {
                println!("MasterPW checking master pw: {}", err);
                master_pw.zeroize();
                continue;
            };
            let sec_key;
            (sec_key, pub_key, wrapped_user_key) = match general_login(master_pw, db_header.db_salt.clone()) {
                Ok(v) => { v }
                Err(e) => {
                    println!("Error checking master pw: {}", e);
                    continue;
                }
            };
            db = match decrypt_db(encrypted_db.as_ref().unwrap(), sec_key) {
                Ok(v) => { v }
                Err(e) => {
                    println!("Error decrypting db: {}", e);
                    pub_key.zeroize();
                    wrapped_user_key.zeroize();
                    continue;
                }
            };

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
                        let mut master_pw = String::new();
                        stdin().read_line(&mut master_pw).unwrap();
                        if let Err(err) = master_pw_validation(&master_pw) {
                            println!("MasterPW creation error: {}", err);
                            master_pw.zeroize();
                            continue;
                        };

                        print!("Please confirm master password: ");
                        io::stdout().flush().unwrap();
                        let mut master_pw_confirm = String::new();
                        stdin().read_line(&mut master_pw_confirm).unwrap();

                        let is_match = master_pw == master_pw_confirm;
                        master_pw.zeroize();
                        if is_match {
                            println!("password is missmatch");
                            master_pw_confirm.zeroize();
                            continue;
                        }
                        (pub_key, db_header.db_salt, wrapped_user_key) = match change_master_pw(&mut db, master_pw_confirm, wrapped_user_key.clone()) {
                            Ok(v) => v,
                            Err(e) => {
                                println!("Error setting master pw: {}", e);
                                continue;
                            }
                        };

                        let encryted_db = encrypt_db(&db, &pub_key);

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
                        let encryted_db = encrypt_db(&db, &pub_key);

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
                        let encryted_db = encrypt_db(&db, &pub_key);

                        if let Err(e) = save_db(db_header, encryted_db) {
                            println!("Error saving db: {}", e);
                            continue;
                        }
                        // } else {
                        //     mark_as_graceful_exited_to_file().ok();
                        // }
                        wrapped_user_key.zeroize();
                        pub_key.zeroize();
                        drop(db);
                        exit(0);
                    }
                    UserRequest::ExitAppWithoutSave => {
                        // if !should_save_db {
                        mark_as_graceful_exited_to_file().ok();
                        // }
                        wrapped_user_key.zeroize();
                        pub_key.zeroize();
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