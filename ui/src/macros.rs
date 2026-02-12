#[macro_export]
macro_rules! user_interface_horizontal_input_strings {
    ($user_interface:expr $(, ($label_string:expr, $mut_string:expr))* $(,)?) => {
        $(
            $user_interface.horizontal(|ui| {
                ui.label($label_string);
                ui.text_edit_singleline($mut_string);
            });
        )*
    }
}

#[macro_export]
macro_rules! result_function {
    ($result_function:expr, $input:ident, $($error_message:expr)?, $control:tt, ($($zeroizes:ident),* $(,)?)) => {
        match $result_function($input) {
            Ok(value) => value,
            Err(error) => {
                $(
                    $error_message = error.to_string();
                )?
                $(
                    $zeroizes.zeroize();
                )*
                $control
            }
        }
    }
}

#[macro_export]
macro_rules! command_build {
    (
        $context:ident, $button:ident, $command_function:ident, $window_open:expr, $viewport_identifier:expr, $viewport_title:expr, $screen_name:expr, $error_message:expr, $($data_base:expr)?, $($wrapped_user_key:expr)?,
        $((
            $input_value_modifier:expr,
            $input_value_expr_name:expr,
            $input_value_ident_name:ident,
            $result_function:expr, $(,)?
            $((
                $zeroize:ident $(,)?
            ))?
        )),* $(,)?
    ) => {
        if $button.clicked() {
            $window_open = true;
        }
        if $window_open {
            $context.show_viewport_immediate(
                egui::ViewportId::from_hash_of($viewport_identifier),
                egui::ViewportBuilder::default().with_title($viewport_title),
                |ctx, _| {
                    if ctx.input(|input_state| input_state.viewport().close_requested()) {
                        $window_open = false;
                    }
                    egui::CentralPanel::default().show(ctx, |ui| {
                        $(
                            let $input_value_ident_name = $input_value_modifier;
                        )*
                        ui.label($screen_name);
                        user_interface_horizontal_input_strings!(
                            ui,
                            $(($input_value_expr_name, $input_value_ident_name),)*
                        );
                        ui.label(&$error_message);
                        if ui.button("Accept").clicked() {
                            if false $(|| $input_value_ident_name.is_empty())* {
                                $error_message = "empty input!".to_string()
                            }
                            $(
                                let $input_value_ident_name = result_function!($result_function, $input_value_ident_name, $error_message, return, ($($zeroize,)*));
                            )*
                            if let Err(e) = $command_function($($data_base,)? $(&$input_value_ident_name, )* $($wrapped_user_key)?) {
                                println!("Error adding password: {}", e);
                            }
                            if let Err(err) = mark_as_ungraceful_exited_to_file() {
                                println!("Error saving status: {}", err);
                            }
                        }
                    })
                }
            );
        }
    }
}