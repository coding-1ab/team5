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
