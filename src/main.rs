mod ui;

fn main() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions::default();

    eframe::run_native(
        "eframe example",
        options,
        Box::new(|_cc| Ok(Box::new(ui::GraphicalUserInterface::default()))),
    )
}