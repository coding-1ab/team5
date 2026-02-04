use single_instance::SingleInstance;


#[cfg(not(target_pointer_width = "64"))]
compile_error!("이 코드는 64비트 환경(usize가 8바이트)에서만 컴파일됩니다.");


fn main() -> std::io::Result<()> {
    let instance = SingleInstance::new("team-5").unwrap();
    if !instance.is_single() {
        return Ok(())
    }


    cli::cli_app();

    Ok(())
}