use log::error;
use single_instance::SingleInstance;

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
    use rkyv::rancor::ResultExt;
    use team5::master_secrets::{_manual_zeroize, decrypt_db, set_master_pw_and_1st_login};
    use team5::data_base::{add_password, explor_db, SiteName, UserID, UserPW, DB};
    use team5::file_io::{load_db, FileIOWarn};
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
                // 에러 e 표시
                return;
            }
        };
        // user_warn 표시

        let mut db: DB;
        let mut ecies_keys;
        let mut ecies_key_salt= Salt::default();
        let mut wrapped_user_key = WrappedUserKey::default();
        if is_first_login {
            loop {
                let raw_master_pw = String::from("12341234"); // 입력창 통해 마스터 비번 입력
                (ecies_keys, ecies_key_salt, wrapped_user_key) = match set_master_pw_and_1st_login(raw_master_pw) {
                    Ok(v) => {v}
                    Err(e) => {
                        // 에러 e 표시
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
                        // 에러 e 표시
                        continue;
                    }
                };
                db = match decrypt_db(&encrypted_db.as_ref().unwrap(), ecies_keys.sk) {
                    Ok(v) => { v }
                    Err(e) => {
                        // 에러 e 표시
                        continue;
                    }
                };
                drop(encrypted_db);
                break;
            }
        }
        ///////////////////
        add_password(&mut db,
                     SiteName::new("www.123.com").unwrap(),
                     UserID::new("id1111").unwrap(), UserPW::new("pw123").unwrap(),
                     &wrapped_user_key).expect_err("Error when adding password");
        add_password(&mut db,
                     SiteName::new("www.123.com").unwrap(),
                     UserID::new("id2222").unwrap(), UserPW::new("pw456").unwrap(),
                     &wrapped_user_key).unwrap();
        explor_db(&mut db, "www.123.com", &wrapped_user_key);
    }
}
