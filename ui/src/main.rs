use single_instance::SingleInstance;

mod graphical_user_interface;

fn main() {
    let instance = SingleInstance::new("team5").unwrap();
    if !instance.is_single() {
        return;
    }

    #[cfg(feature = "gui")]
    {
        use graphical_user_interface::GraphicalUserInterface;
        let options = eframe::NativeOptions::default();
        eframe::run_native(
            "eframe example",
            options,
            Box::new(|_cc| Ok(Box::new(GraphicalUserInterface::default()))),
        ).unwrap()
    }
}