use std::{
    env,
    path::{Path, PathBuf},
    process::Command,
};

struct Target
{
    name: String,
    is_release: bool,
}

impl Target
{
    fn get() -> Self
    {
        let mut target = env::var("TARGET").unwrap();

        if target.starts_with("riscv")
        {
            let mut split = target.split('-');
            let arch = split.next().unwrap();
            let bitness = &arch[5..7];
            let rest = split.collect::<Vec<_>>().join("-");
            target = format!("riscv{bitness}-{rest}");
        }

        Self {
            name: target,
            is_release: env::var("PROFILE").unwrap() == "release",
        }
    }
}

fn compile_libsodium_traditional(
    target: &str,
    source_dir: &Path,
    install_dir: &Path,
) -> Result<PathBuf, String>
{
    use std::fs;

    // 🔥 완전 고정된 빌드 환경
    let cflags = "-O2 -fPIC -fno-omit-frame-pointer -fno-strict-aliasing";
    let ldflags = "";

    let host_arg = format!("--host={target}");
    let prefix_arg = format!("--prefix={}", install_dir.to_str().unwrap());

    // 🔥 1단계: autotools 재생성 (필수)
    let status = Command::new("autoreconf")
        .current_dir(source_dir)
        .arg("-fi")
        .status()
        .map_err(|e| format!("autoreconf failed: {e}"))?;

    if !status.success()
    {
        return Err("autoreconf failed".into());
    }

    // 🔥 2단계: configure
    let status = Command::new("./configure")
        .current_dir(source_dir)
        .env("CFLAGS", cflags)
        .env("LDFLAGS", ldflags)
        .arg("--disable-shared")
        .arg("--enable-static")
        .arg("--disable-ssp")
        .arg("--disable-dependency-tracking")
        .arg(&prefix_arg)
        .arg(&host_arg)
        .status()
        .map_err(|e| format!("configure failed: {e}"))?;

    if !status.success()
    {
        return Err("configure failed".into());
    }

    // 🔥 3단계: clean (이전 빌드 잔재 제거)
    let _ = Command::new("make")
        .current_dir(source_dir)
        .arg("clean")
        .status();

    // 🔥 4단계: build
    let status = Command::new("make")
        .current_dir(source_dir)
        .arg(format!("-j{}", env::var("NUM_JOBS").unwrap_or("1".into())))
        .status()
        .map_err(|e| format!("make failed: {e}"))?;

    if !status.success()
    {
        return Err("make failed".into());
    }

    // 🔥 5단계: install
    let status = Command::new("make")
        .current_dir(source_dir)
        .arg("install")
        .status()
        .map_err(|e| format!("make install failed: {e}"))?;

    if !status.success()
    {
        return Err("make install failed".into());
    }

    Ok(install_dir.join("lib"))
}

fn get_cargo_install_dir() -> PathBuf
{
    PathBuf::from(env::var("OUT_DIR").unwrap()).join("installed")
}

fn install_from_source() -> Result<(), String>
{
    use libflate::gzip::Decoder;
    use std::fs;
    use tar::Archive;

    let target = Target::get().name;

    let basedir = "libsodium-stable";
    let filename = "LATEST.tar.gz";
    let sig = "LATEST.tar.gz.minisig";

    let archive_bin = retrieve_and_verify_archive(filename, sig);

    let mut install_dir = get_cargo_install_dir();
    let mut source_dir = PathBuf::from(env::var("OUT_DIR").unwrap()).join("source");

    fs::create_dir_all(&install_dir).unwrap();
    fs::create_dir_all(&source_dir).unwrap();

    let gz = Decoder::new(std::io::Cursor::new(archive_bin)).unwrap();
    let mut archive = Archive::new(gz);
    archive.unpack(&source_dir).unwrap();

    source_dir.push(basedir);

    let lib_dir = compile_libsodium_traditional(&target, &source_dir, &install_dir)?;

    println!("cargo:rustc-link-lib=static=sodium");
    println!("cargo:rustc-link-search=native={}", lib_dir.display());

    let include_dir = source_dir.join("src/libsodium/include");

    println!("cargo:include={}", include_dir.display());

    Ok(())
}

fn retrieve_and_verify_archive(_: &str, _: &str) -> Vec<u8>
{
    panic!("archive fetch 생략 (기존 코드 그대로 유지 가능)");
}

fn main()
{
    println!("cargo:rerun-if-env-changed=SODIUM_LIB_DIR");

    let res = install_from_source();

    if let Err(e) = res
    {
        panic!("libsodium build failed: {}", e);
    }
}