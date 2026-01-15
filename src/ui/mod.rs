// todo
// 사이트 이름 + 계정 정보 주면 저장
// 사이트 이름 주면 계정 정보 불러오기

// 흠 뭐부터 하지

pub mod graphical_user_interface;

struct CharacterUserInterface {
    secrets: Secrets
}

impl CharacterUserInterface {

}

struct UserInterface {
    #[cfg(feature = "GraphicalUserInterface")]
    graphical_user_interface: GraphicalUserInterface,
    #[cfg(feature = "CharacterUserInterface")]
    character_user_interface: CharacterUserInterface
}

