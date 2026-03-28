use single_instance::SingleInstance;
use libsodium_sys::rust_wrappings::init::sodium_init;


fn main() -> std::io::Result<()> {
    // let instance = SingleInstance::new("team-5").unwrap();
    // if !instance.is_single() {
    //     return Ok(())
    // }

    sodium_init().expect("TODO: panic message");
    cli::cli_app();

    Ok(())
}