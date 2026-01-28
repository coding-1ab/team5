// todo
// 사이트 이름 + 계정 정보 주면 저장
// 사이트 이름 주면 계정 정보 불러오기

// 흠 뭐부터 하지

use crate::data_base::DB;

#[cfg(feature = "gui")]
pub mod graphical_user_interface;

struct CharacterUserInterface {
    db: DB
}

impl CharacterUserInterface {

}

struct UserInterface {
    #[cfg(feature = "gui")]
    graphical_user_interface: graphical_user_interface::GraphicalUserInterface,
    #[cfg(feature = "cui")]
    character_user_interface: CharacterUserInterface
}

