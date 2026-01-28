use log::error;
use single_instance::SingleInstance;

fn main() {
    let instance = SingleInstance::new("team-5").unwrap();
    if size_of::<usize>() != 64 { error!("Unsupported Architecture") };
    
    if !instance.is_single() {
        // error!("This instance is not a single.");
        // return Ok(());
    }

    #[cfg(feature = "gui")]
    {
        use team5::ui::graphical_user_interface::GraphicalUserInterface;
        let options = eframe::NativeOptions::default();
        eframe::run_native(
            "eframe example",
            options,
            Box::new(|_cc| Ok(Box::new(GraphicalUserInterface::default()))),
        ).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use team5::crypto::decrypt_db;
    use team5::data_base::DB;
    use team5::file_io::{load_db, FileIOWarn};
    use team5::header::Salt;
    use team5::master_secrets::{set_master_pw, EciesKeyPair};
    use team5::user_secrets::{UserKey, WrappedUserKey};

    use super::*;

    #[test]
    fn without_gui() -> () {
        let instance = SingleInstance::new("team-5").unwrap();
        if size_of::<usize>() != 64 { error!("Unsupported Architecture") };

        if !instance.is_single() {
            error!("This instance is not a single.");
            return ();
        }

        let (first_login, user_wran, mut db_header, encrypted_db)
            = match load_db() {
            Ok(v) => {v}
            Err(e) => {
                // 에러 e 표시
                return;
            }
        };
        // user_warn 표시

        let mut db: DB;
        let mut ecies_keys = EciesKeyPair::void();
        let mut ecies_key_salt= Salt::default();
        let mut wrapped_user_key = WrappedUserKey::default();
        if first_login {
            loop {
                let raw_master_pw = String::from("12341234"); // 입력창 통해 마스터 비번 입력
                (ecies_keys, ecies_key_salt, wrapped_user_key) = match set_master_pw(raw_master_pw) {
                    Ok(v) => {v}
                    Err(e) => {
                        // 에러 e 표시
                        continue;
                    }
                };
                break;
            }
            db_header.db_salt = ecies_key_salt;
            db = DB::new();
        } else {
            db = match decrypt_db(&encrypted_db.unwrap(), ecies_keys.sk) {
                Ok(v) => {v}
                Err(e) => {
                    // 에러 e 표시
                    return;
                }
            };
        }


    }
}
