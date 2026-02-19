use eframe::egui::{ViewportBuilder, ViewportId};
use eframe::egui::Context;

pub struct ViewportError {
    viewport_id: ViewportId,
    viewport_builder: ViewportBuilder,
    error_message: String,
}

impl ViewportError {
    pub fn new(viewport_id: ViewportId, viewport_builder: ViewportBuilder, error_message: String) -> Self {
        Self { viewport_id, viewport_builder, error_message }
    }
    
    pub fn show_error(self, context: &Context, mut accept_execute: impl FnMut()) {
        context.show_viewport_immediate(
            self.viewport_id,
            self.viewport_builder,
            |ctx, _| {
                eframe::egui::CentralPanel::default().show(ctx, |ui| {
                    ui.label(&self.error_message);
                    if ui.button("accept").clicked() {
                        accept_execute();
                    }
                })
            }
        );
    }
}