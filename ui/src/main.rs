use single_instance::SingleInstance;

use ui::graphical_user_interface::GraphicalUserInterface;

fn main() {
    let instance = SingleInstance::new("team5").unwrap();
    if !instance.is_single() {
        return;
    }

    #[cfg(feature = "gui")]
    {
        let options = eframe::NativeOptions::default();
        eframe::run_native(
            "eframe example",
            options,
            Box::new(|_cc| Ok(Box::new(GraphicalUserInterface::default()))),
        ).unwrap()
    }
}