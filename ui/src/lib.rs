#![deny(unused_mut)]
#![deny(clippy::cognitive_complexity)]
#![deny(clippy::complexity)]
#![deny(clippy::too_many_lines)]

use engine::data_base::DB;

#[cfg(feature = "gui")]
pub mod graphical_user_interface;
mod command_builder;

struct CharacterUserInterface {
    db: DB
}

impl CharacterUserInterface {

}

struct UserInterface {
    #[cfg(feature = "gui")]
    graphical_user_interface: graphical_user_interface::GraphicalUserInterface,
    #[cfg(feature = "cui")]
    character_user_interface: CharacterUserInterface,
    //_phantom_data: PhantomData<()>
}

