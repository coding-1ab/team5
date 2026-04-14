use std::{
    env,
    fs,
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

        // RISC-V triple 보정
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
            is_release: env::var("PROFILE").unwrap_or_else(|_| "debug".to_string()) == "release",
        }
    }
}

fn manifest_dir() -> PathBuf
{
    PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string()))
}

fn local_file_candidates(filename: &str) -> Vec<PathBuf>
{
    let mut candidates = Vec::new();

    if let Ok(dist_dir) = env::var("SODIUM_DIST_DIR")
    {
        candidates.push(PathBuf::from(dist_dir).join(filename));
    }

    candidates.push(manifest_dir().join(filename));

    if let Ok(cwd) = env::current_dir()
    {
        candidates.push(cwd.join(filename));
    }

    candidates
}

fn find_local_file(filename: &str) -> Result<PathBuf, String>
{
    for candidate in local_file_candidates(filename)
    {
        if candidate.is_file()
        {
            return Ok(candidate);
        }
    }

    Err(format!(
        "로컬 파일을 찾지 못했습니다: {}. SODIUM_DIST_DIR 또는 프로젝트 루트에 파일이 있어야 합니다.",
        filename
    ))
}

fn retrieve_and_verify_archive(filename: &str, signature_filename: &str) -> Result<Vec<u8>, String>
{
    use minisign_verify::{PublicKey, Signature};
    use std::io::Read;

    let pk = PublicKey::from_base64(
        "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3",
    )
        .map_err(|e| format!("minisign 공개키 파싱 실패: {e}"))?;

    let archive_path = find_local_file(filename)?;
    let signature_path = find_local_file(signature_filename)?;

    let mut archive_bin = vec![];
    fs::File::open(&archive_path)
        .map_err(|e| format!("아카이브 열기 실패 [{}]: {e}", archive_path.display()))?
        .read_to_end(&mut archive_bin)
        .map_err(|e| format!("아카이브 읽기 실패 [{}]: {e}", archive_path.display()))?;

    let signature = Signature::from_file(&signature_path)
        .map_err(|e| format!("서명 파일 열기 실패 [{}]: {e}", signature_path.display()))?;

    pk.verify(&archive_bin, &signature, false)
        .map_err(|e| format!("아카이브 서명 검증 실패: {e}"))?;

    Ok(archive_bin)
}

fn get_cargo_install_dir() -> PathBuf
{
    PathBuf::from(env::var("OUT_DIR").unwrap()).join("installed")
}

fn get_cargo_source_dir() -> PathBuf
{
    PathBuf::from(env::var("OUT_DIR").unwrap()).join("source")
}

fn source_root_from_extract(root: &Path) -> PathBuf
{
    let candidate = root.join("libsodium-stable");
    if candidate.join("configure").is_file()
    {
        candidate
    }
    else
    {
        root.to_path_buf()
    }
}

fn extract_tar_gz_to_dir(archive_bin: Vec<u8>, output_dir: &Path) -> Result<PathBuf, String>
{
    use libflate::gzip::Decoder;
    use tar::Archive;

    let _ = fs::remove_dir_all(output_dir);
    fs::create_dir_all(output_dir)
        .map_err(|e| format!("소스 디렉터리 생성 실패 [{}]: {e}", output_dir.display()))?;

    let gz_decoder = Decoder::new(std::io::Cursor::new(archive_bin))
        .map_err(|e| format!("gzip 디코더 생성 실패: {e}"))?;
    let mut archive = Archive::new(gz_decoder);

    archive
        .unpack(output_dir)
        .map_err(|e| format!("tar 압축 해제 실패 [{}]: {e}", output_dir.display()))?;

    Ok(source_root_from_extract(output_dir))
}

fn extract_zip_to_dir(archive_bin: Vec<u8>, output_dir: &Path) -> Result<(), String>
{
    use zip::read::ZipArchive;

    let _ = fs::remove_dir_all(output_dir);
    fs::create_dir_all(output_dir)
        .map_err(|e| format!("설치 디렉터리 생성 실패 [{}]: {e}", output_dir.display()))?;

    let mut archive = ZipArchive::new(std::io::Cursor::new(archive_bin))
        .map_err(|e| format!("zip 아카이브 열기 실패: {e}"))?;

    archive
        .extract(output_dir)
        .map_err(|e| format!("zip 압축 해제 실패 [{}]: {e}", output_dir.display()))
}

fn get_precompiled_lib_dir_msvc_win32(install_dir: &Path) -> PathBuf {
    if Target::get().is_release {
        install_dir.join("libsodium/Win32/Release/v143/static/")
    } else {
        install_dir.join("libsodium/Win32/Debug/v143/static/")
    }
}

fn get_precompiled_lib_dir_msvc_x64(install_dir: &Path) -> PathBuf {
    if Target::get().is_release {
        install_dir.join("libsodium/x64/Release/v143/static/")
    } else {
        install_dir.join("libsodium/x64/Debug/v143/static/")
    }
}

fn get_precompiled_lib_dir_msvc_arm64(install_dir: &Path) -> PathBuf {
    if Target::get().is_release {
        install_dir.join("libsodium/ARM64/Release/v143/static/")
    } else {
        install_dir.join("libsodium/ARM64/Debug/v143/static/")
    }
}

fn extract_libsodium_precompiled_msvc(install_dir: &Path) -> Result<PathBuf, String>
{
    let basename = "libsodium-1.0.21-stable-msvc";
    let filename = format!("{}.zip", basename);
    let signature_filename = format!("{}.zip.minisig", basename);

    let archive_bin = retrieve_and_verify_archive(&filename, &signature_filename)?;
    extract_zip_to_dir(archive_bin, install_dir)?;

    match Target::get().name.as_str() {
        "i686-pc-windows-msvc" => Ok(get_precompiled_lib_dir_msvc_win32(install_dir)),
        "x86_64-pc-windows-msvc" => Ok(get_precompiled_lib_dir_msvc_x64(install_dir)),
        "aarch64-pc-windows-msvc" => Ok(get_precompiled_lib_dir_msvc_arm64(install_dir)),
        _ => Err("Unsupported MSVC target".to_string()),
    }
}

fn extract_libsodium_precompiled_mingw(install_dir: &Path) -> Result<PathBuf, String>
{
    let basename = "libsodium-1.0.21-stable-mingw";
    let filename = format!("{}.tar.gz", basename);
    let signature_filename = format!("{}.tar.gz.minisig", basename);

    let archive_bin = retrieve_and_verify_archive(&filename, &signature_filename)?;
    extract_tar_gz_to_dir(archive_bin, install_dir)?;

    match Target::get().name.as_str() {
        "i686-pc-windows-gnu" => Ok(install_dir.join("libsodium-win32/lib")),
        "x86_64-pc-windows-gnu" => Ok(install_dir.join("libsodium-win64/lib")),
        _ => Err("Unsupported MinGW target".to_string()),
    }
}

fn build_libsodium_from_source(target: &str, source_dir: &Path, install_dir: &Path) -> Result<PathBuf, String>
{
    let build_compiler = cc::Build::new().get_compiler();
    let mut compiler = build_compiler.path().to_str().unwrap().to_string();

    // 외부 환경에 흔들리지 않도록 고정
    let mut cflags = String::from("-O2 -fno-strict-aliasing -fno-omit-frame-pointer -UNDEBUG");
    let ldflags = String::new();

    let host_arg = format!("--host={target}");
    let prefix_arg = format!("--prefix={}", install_dir.to_str().unwrap());

    if target.contains("i686")
    {
        compiler += " -m32 -maes";
        cflags += " -march=i686";
    }

    let mut configure_cmd = Command::new("./configure");
    configure_cmd
        .current_dir(source_dir)
        .env("CC", &compiler)
        .env("CFLAGS", &cflags)
        .env("LDFLAGS", &ldflags)
        .arg("--disable-shared")
        .arg("--enable-static")
        .arg("--disable-ssp")
        .arg("--disable-dependency-tracking")
        .arg(&prefix_arg)
        .arg(&host_arg);

    let configure_output = configure_cmd
        .output()
        .map_err(|e| format!("configure 실행 실패: {e}"))?;

    if !configure_output.status.success()
    {
        return Err(format!(
            "CONFIGURE FAILED\nCFLAGS={}\nCC={}\n{}\n{}",
            cflags,
            compiler,
            String::from_utf8_lossy(&configure_output.stdout),
            String::from_utf8_lossy(&configure_output.stderr),
        ));
    }

    let jobs = env::var("NUM_JOBS")
        .or_else(|_| env::var("CARGO_BUILD_JOBS"))
        .unwrap_or_else(|_| "1".to_string());

    let make_clean = Command::new("make")
        .current_dir(source_dir)
        .arg("clean")
        .status();

    let _ = make_clean;

    let make_output = Command::new("make")
        .current_dir(source_dir)
        .arg(format!("-j{jobs}"))
        .status()
        .map_err(|e| format!("make 실행 실패: {e}"))?;

    if !make_output.success()
    {
        return Err("make 실패".to_string());
    }

    let install_output = Command::new("make")
        .current_dir(source_dir)
        .arg("install")
        .status()
        .map_err(|e| format!("make install 실행 실패: {e}"))?;

    if !install_output.success()
    {
        return Err("make install 실패".to_string());
    }

    Ok(install_dir.join("lib"))
}

fn build_source_install() -> Result<(PathBuf, PathBuf), String>
{
    let target = Target::get().name;

    let basedir = "libsodium-stable";
    let filename = "LATEST.tar.gz";
    let signature_filename = "LATEST.tar.gz.minisig";

    let archive_bin = retrieve_and_verify_archive(filename, signature_filename)?;

    let mut install_dir = get_cargo_install_dir();
    let mut source_dir = get_cargo_source_dir();

    if install_dir.to_str().unwrap_or_default().contains(' ')
    {
        let fallback_root = env::temp_dir().join("libsodium_build").join(&target);
        install_dir = fallback_root.join("installed");
        source_dir = fallback_root.join("source");

        println!(
            "cargo:warning=기본 빌드 경로에 공백이 있어 임시 경로를 사용합니다: {}",
            fallback_root.display()
        );
    }

    fs::create_dir_all(&install_dir)
        .map_err(|e| format!("설치 디렉터리 생성 실패 [{}]: {e}", install_dir.display()))?;
    fs::create_dir_all(&source_dir)
        .map_err(|e| format!("소스 디렉터리 생성 실패 [{}]: {e}", source_dir.display()))?;

    let source_root = extract_tar_gz_to_dir(archive_bin, &source_dir)?;
    let source_root = if source_root.join(basedir).is_dir() {
        source_root.join(basedir)
    } else {
        source_root
    };

    let lib_dir = build_libsodium_from_source(&target, &source_root, &install_dir)?;
    let include_dir = source_root.join("src/libsodium/include");

    Ok((lib_dir, include_dir))
}

fn main()
{
    println!("cargo:rerun-if-env-changed=SODIUM_DIST_DIR");
    println!("cargo:rerun-if-changed=build.rs");

    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set");
    let install_dir = Path::new(&out_dir).join("libsodium");

    let lib_dir = install_dir.join("lib");
    let include_dir = install_dir.join("include");

    let already_built = lib_dir.exists() && include_dir.exists();

    let target = Target::get();

    if !already_built
    {
        std::fs::create_dir_all(&install_dir)
            .expect("failed to create install_dir");

        let result: Result<(), String> = if target.name.contains("windows-msvc")
        {
            match extract_libsodium_precompiled_msvc(&install_dir)
            {
                Ok(extracted_lib_dir) =>
                    {
                        // lib 디렉토리 정규화 (필요시 복사)
                        copy_dir_all(&extracted_lib_dir, &lib_dir).unwrap();
                        Ok(())
                    }
                Err(e) => Err(e.to_string()),
            }
        }
        else if target.name.contains("windows-gnu")
        {
            match extract_libsodium_precompiled_mingw(&install_dir)
            {
                Ok(extracted_lib_dir) =>
                    {
                        copy_dir_all(&extracted_lib_dir, &lib_dir).unwrap();
                        Ok(())
                    }
                Err(e) => Err(e.to_string()),
            }
        }
        else
        {
            match build_source_install()
            {
                Ok((built_lib_dir, built_include_dir)) =>
                    {
                        copy_dir_all(&built_lib_dir, &lib_dir).unwrap();
                        copy_dir_all(&built_include_dir, &include_dir).unwrap();
                        Ok(())
                    }
                Err(e) => Err(e.to_string()),
            }
        };

        if let Err(e) = result
        {
            panic!("libsodium build failed: {}", e);
        }
    }

    println!("cargo:rustc-link-search=native={}", lib_dir.display());

    if target.name.contains("windows-msvc")
    {
        println!("cargo:rustc-link-lib=static=libsodium");
    }
    else
    {
        println!("cargo:rustc-link-lib=static=sodium");
    }

    println!("cargo:include={}", include_dir.display());
}

fn copy_dir_all(src: &Path, dst: &Path) -> Result<(), String>
{
    std::fs::create_dir_all(dst).map_err(|e| e.to_string())?;

    for entry in std::fs::read_dir(src).map_err(|e| e.to_string())?
    {
        let entry = entry.map_err(|e| e.to_string())?;
        let file_type = entry.file_type().map_err(|e| e.to_string())?;

        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());

        if file_type.is_dir()
        {
            copy_dir_all(&src_path, &dst_path)?;
        }
        else
        {
            std::fs::copy(&src_path, &dst_path).map_err(|e| e.to_string())?;
        }
    }

    Ok(())
}