use log::error;
use single_instance::SingleInstance;

fn main() -> Result<(), eframe::Error> {
    let instance = SingleInstance::new("team-5").unwrap();
    if !instance.is_single() {
        // error!("This instance is not a single.");
        // return Ok(());
    }
    let options = eframe::NativeOptions::default();

    eframe::run_native(
        "eframe example",
        options,
        Box::new(|_cc| Ok(Box::new(team5::ui::graphical_user_interface::GraphicalUserInterface::default()))),
    )
}
