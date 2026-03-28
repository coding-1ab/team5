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

        // RISC-V는 Rust와 C 도구체인의 triple 표기가 다를 수 있으므로 보정한다.
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

    let pk = PublicKey::from_base64("RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3")
        .map_err(|e| format!("minisign 공개키 파싱 실패: {e}"))?;

    let archive_path = find_local_file(filename)?;
    let signature_path = find_local_file(signature_filename)?;

    let mut archive_bin = Vec::new();
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

fn find_source_root(extracted_root: &Path) -> Result<PathBuf, String>
{
    let candidates = [
        extracted_root.to_path_buf(),
        extracted_root.join("libsodium-stable"),
        extracted_root.join("libsodium"),
    ];

    for candidate in candidates
    {
        if candidate.join("configure").is_file() || candidate.join("builds").join("msvc").exists()
        {
            return Ok(candidate);
        }
    }

    Err(format!(
        "소스 루트를 찾지 못했습니다: {} 아래에 configure 또는 builds/msvc 가 있어야 합니다.",
        extracted_root.display()
    ))
}

fn find_first_file_with_name(root: &Path, names: &[&str]) -> Option<PathBuf>
{
    let mut stack = vec![root.to_path_buf()];

    while let Some(dir) = stack.pop()
    {
        let entries = match fs::read_dir(&dir)
        {
            Ok(entries) => entries,
            Err(_) => continue,
        };

        for entry in entries.flatten()
        {
            let path = entry.path();

            if path.is_dir()
            {
                stack.push(path);
            }
            else if let Some(file_name) = path.file_name().and_then(|s| s.to_str())
            {
                if names.iter().any(|wanted| *wanted == file_name)
                {
                    return Some(path);
                }
            }
        }
    }

    None
}

fn find_first_file_with_extension(root: &Path, extension: &str) -> Option<PathBuf>
{
    let mut stack = vec![root.to_path_buf()];

    while let Some(dir) = stack.pop()
    {
        let entries = match fs::read_dir(&dir)
        {
            Ok(entries) => entries,
            Err(_) => continue,
        };

        for entry in entries.flatten()
        {
            let path = entry.path();

            if path.is_dir()
            {
                stack.push(path);
            }
            else if path.extension().and_then(|s| s.to_str()) == Some(extension)
            {
                return Some(path);
            }
        }
    }

    None
}

fn run_command_with_fallback(
    candidates: &[&str],
    current_dir: &Path,
    args: &[String],
) -> Result<(), String>
{
    let mut last_error = String::new();

    for cmd in candidates
    {
        let mut command = Command::new(cmd);
        command.current_dir(current_dir);
        command.args(args);

        match command.status()
        {
            Ok(status) if status.success() =>
                {
                    return Ok(());
                }
            Ok(status) =>
                {
                    last_error = format!("명령 [{}] 이(가) 실패했습니다: {}", cmd, status);
                }
            Err(e) =>
                {
                    last_error = format!("명령 [{}] 실행 실패: {e}", cmd);
                }
        }
    }

    Err(last_error)
}

fn autotools_host_triple(target: &str) -> String
{
    match target
    {
        "x86_64-pc-windows-gnu" => "x86_64-w64-mingw32".to_string(),
        "i686-pc-windows-gnu" => "i686-w64-mingw32".to_string(),
        "aarch64-pc-windows-gnu" => "aarch64-w64-mingw32".to_string(),
        _ => target.to_string(),
    }
}

fn compile_libsodium_autotools(
    target: &str,
    source_dir: &Path,
    install_dir: &Path,
) -> Result<PathBuf, String>
{
    // 외부 환경 변수 CFLAGS/LDFLAGS에 의존하지 않도록 고정값을 사용한다.
    let build_compiler = cc::Build::new().get_compiler();
    let mut compiler = build_compiler.path().to_str().unwrap().to_string();

    let mut cflags = String::from("-O2 -fno-strict-aliasing -fno-omit-frame-pointer -fno-stack-protector -UNDEBUG");
    let mut ldflags = String::new();
    let mut configure_extra: Vec<&str> = Vec::new();
    let host_arg;
    let help;

    if target.contains("-wasi")
    {
        // WASI는 Zig 툴체인을 사용한다.
        compiler = "zig cc".to_string();
        cflags += " -target wasm32-wasi";
        ldflags += " -target wasm32-wasi";
        host_arg = "--host=wasm32-wasi".to_string();
        configure_extra.push("--disable-ssp");
        configure_extra.push("--without-pthreads");
        env::set_var("AR", "zig ar");
        env::set_var("RANLIB", "zig ranlib");
        help = "WASI 빌드에는 Zig SDK가 필요합니다.";
    }
    else if target.contains("-ios")
    {
        // iOS는 Xcode SDK 경로를 사용한다.
        let xcode_select_output = Command::new("xcode-select")
            .arg("-p")
            .output()
            .map_err(|e| format!("xcode-select 실행 실패: {e}"))?;

        if !xcode_select_output.status.success()
        {
            return Err("xcode-select -p 실행에 실패했습니다.".to_string());
        }

        let xcode_dir = std::str::from_utf8(&xcode_select_output.stdout)
            .map_err(|e| format!("xcode-select 출력 UTF-8 변환 실패: {e}"))?
            .trim()
            .to_string();

        let sdk_dir_simulator = Path::new(&xcode_dir)
            .join("Platforms/iPhoneSimulator.platform/Developer/SDKs/iPhoneSimulator.sdk")
            .to_str()
            .unwrap()
            .to_string();

        let sdk_dir_ios = Path::new(&xcode_dir)
            .join("Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk")
            .to_str()
            .unwrap()
            .to_string();

        let ios_simulator_version_min = "9.0.0";
        let ios_version_min = "9.0.0";

        match target
        {
            "aarch64-apple-ios" =>
                {
                    cflags += " -arch arm64";
                    cflags += &format!(" -isysroot {sdk_dir_ios}");
                    cflags += &format!(" -mios-version-min={ios_version_min}");
                    host_arg = "--host=aarch64-apple-darwin".to_string();
                }
            "armv7-apple-ios" =>
                {
                    cflags += " -arch armv7";
                    cflags += &format!(" -isysroot {sdk_dir_ios}");
                    cflags += &format!(" -mios-version-min={ios_version_min}");
                    cflags += " -mthumb";
                    host_arg = "--host=arm-apple-darwin".to_string();
                }
            "armv7s-apple-ios" =>
                {
                    cflags += " -arch armv7s";
                    cflags += &format!(" -isysroot {sdk_dir_ios}");
                    cflags += &format!(" -mios-version-min={ios_version_min}");
                    cflags += " -mthumb";
                    host_arg = "--host=arm-apple-darwin".to_string();
                }
            "x86_64-apple-ios" =>
                {
                    cflags += " -arch x86_64";
                    cflags += &format!(" -isysroot {sdk_dir_simulator}");
                    cflags += &format!(" -mios-simulator-version-min={ios_simulator_version_min}");
                    host_arg = "--host=x86_64-apple-darwin".to_string();
                }
            "aarch64-apple-ios-sim" =>
                {
                    cflags += " -arch arm64";
                    cflags += &format!(" -isysroot {sdk_dir_simulator}");
                    cflags += &format!(" -mios-simulator-version-min={ios_simulator_version_min}");
                    host_arg = "--host=aarch64-apple-darwin".to_string();
                }
            _ =>
                {
                    return Err(format!("알 수 없는 iOS 타깃: {}", target));
                }
        }

        help = "";
    }
    else
    {
        if target.contains("i686")
        {
            compiler += " -m32 -maes";
            cflags += " -march=i686";
        }

        host_arg = format!("--host={}", autotools_host_triple(target));

        help = if target != env::var("HOST").unwrap_or_default()
        {
            "크로스 컴파일 중입니다. 필요한 툴체인이 설치되어 있어야 합니다."
        }
        else
        {
            ""
        };
    }

    let prefix_arg = format!("--prefix={}", install_dir.to_str().unwrap());

    // configure는 셸을 통해 실행한다. Windows GNU 환경도 이 방식이면 동작한다.
    let mut configure_cmd = Command::new("sh");
    configure_cmd
        .current_dir(source_dir)
        .env("CC", &compiler)
        .env("CFLAGS", &cflags)
        .env("LDFLAGS", &ldflags)
        .arg("./configure")
        .arg(&prefix_arg)
        .arg(&host_arg)
        .arg("--disable-shared")
        .arg("--enable-static")
        .arg("--disable-ssp")
        .arg("--disable-dependency-tracking");

    for extra in configure_extra
    {
        configure_cmd.arg(extra);
    }

    let configure_output = configure_cmd
        .output()
        .map_err(|e| format!("./configure 실행 실패: {e}\n{help}"))?;

    if !configure_output.status.success()
    {
        return Err(format!(
            "configure 실패\nCC={}\nCFLAGS={}\nLDFLAGS={}\n{}\n{}\n{}",
            compiler,
            cflags,
            ldflags,
            String::from_utf8_lossy(&configure_output.stdout),
            String::from_utf8_lossy(&configure_output.stderr),
            help
        ));
    }

    // 이전 산출물이 있으면 정리한다.
    let _ = run_command_with_fallback(
        &["make", "mingw32-make"],
        source_dir,
        &["clean".to_string()],
    );

    let jobs = env::var("NUM_JOBS")
        .or_else(|_| env::var("CARGO_BUILD_JOBS"))
        .unwrap_or_else(|_| "1".to_string());

    run_command_with_fallback(
        &["make", "mingw32-make"],
        source_dir,
        &[format!("-j{jobs}")],
    )
        .map_err(|e| format!("make 실패: {e}"))?;

    run_command_with_fallback(
        &["make", "mingw32-make"],
        source_dir,
        &["install".to_string()],
    )
        .map_err(|e| format!("make install 실패: {e}"))?;

    Ok(install_dir.join("lib"))
}

fn find_msvc_solution(source_root: &Path) -> Result<PathBuf, String>
{
    let explicit_candidates = [
        source_root.join("builds/msvc/vs2022/libsodium.sln"),
        source_root.join("builds/msvc/vs2019/libsodium.sln"),
        source_root.join("builds/msvc/vs2017/libsodium.sln"),
        source_root.join("builds/msvc/vs2015/libsodium.sln"),
        source_root.join("builds/msvc/libsodium.sln"),
    ];

    for candidate in explicit_candidates
    {
        if candidate.is_file()
        {
            return Ok(candidate);
        }
    }

    let builds_dir = source_root.join("builds").join("msvc");
    if builds_dir.exists()
    {
        if let Some(found) = find_first_file_with_extension(&builds_dir, "sln")
        {
            return Ok(found);
        }
    }

    Err(format!(
        "MSVC 솔루션 파일을 찾지 못했습니다: {}",
        source_root.display()
    ))
}

fn build_msvc_from_source(target: &str, source_root: &Path) -> Result<PathBuf, String>
{
    let solution = find_msvc_solution(source_root)?;

    let platform = match target
    {
        "i686-pc-windows-msvc" => "Win32",
        "x86_64-pc-windows-msvc" => "x64",
        "aarch64-pc-windows-msvc" => "ARM64",
        _ => return Err(format!("지원하지 않는 MSVC 타깃: {}", target)),
    };

    let config = if Target::get().is_release
    {
        "Release"
    }
    else
    {
        "Debug"
    };

    let build_args = vec![
        solution.to_str().unwrap().to_string(),
        "/m".to_string(),
        format!("/p:Configuration={config}"),
        format!("/p:Platform={platform}"),
    ];

    let msbuild_result = run_command_with_fallback(
        &["msbuild", "dotnet"],
        solution.parent().unwrap_or(source_root),
        &build_args,
    );

    match msbuild_result
    {
        Ok(()) =>
            {
                // 빌드 산출물에서 정적 라이브러리 위치를 찾는다.
                let lib_candidates = [
                    "libsodium.lib",
                    "libsodium_static.lib",
                    "sodium.lib",
                    "libsodium.a",
                    "sodium.a",
                ];

                if let Some(lib_path) = find_first_file_with_name(source_root, &lib_candidates)
                {
                    if let Some(parent) = lib_path.parent()
                    {
                        return Ok(parent.to_path_buf());
                    }
                }

                Err(format!(
                    "MSVC 빌드 후 정적 라이브러리를 찾지 못했습니다: {}",
                    source_root.display()
                ))
            }
        Err(e) =>
            {
                Err(format!("msbuild 실패: {e}"))
            }
    }
}

fn build_source_archive_to_dir(
    archive_bin: Vec<u8>,
    output_root: &Path,
) -> Result<PathBuf, String>
{
    use libflate::gzip::Decoder;
    use tar::Archive;

    let _ = fs::remove_dir_all(output_root);
    fs::create_dir_all(output_root)
        .map_err(|e| format!("소스 출력 디렉터리 생성 실패 [{}]: {e}", output_root.display()))?;

    let gz_decoder = Decoder::new(std::io::Cursor::new(archive_bin))
        .map_err(|e| format!("gzip 디코더 생성 실패: {e}"))?;
    let mut archive = Archive::new(gz_decoder);
    archive
        .unpack(output_root)
        .map_err(|e| format!("소스 압축 해제 실패 [{}]: {e}", output_root.display()))?;

    find_source_root(output_root)
}

fn build_libsodium_from_source(
    target: &str,
    source_root: &Path,
    install_dir: &Path,
) -> Result<PathBuf, String>
{
    if target.contains("windows-msvc")
    {
        build_msvc_from_source(target, source_root)
    }
    else
    {
        compile_libsodium_autotools(target, source_root, install_dir)
    }
}

fn get_cargo_install_dir() -> PathBuf
{
    PathBuf::from(env::var("OUT_DIR").unwrap()).join("installed")
}

fn install_from_source() -> Result<(), String>
{
    let target = Target::get().name;

    let install_dir = get_cargo_install_dir();
    let mut source_root: PathBuf;

    // 설치 경로에 공백이 있으면 임시 경로로 우회한다.
    let mut effective_install_dir = install_dir.clone();
    let mut effective_source_dir = PathBuf::from(env::var("OUT_DIR").unwrap()).join("source");

    if effective_install_dir.to_str().unwrap_or_default().contains(' ')
    {
        let fallback_root = PathBuf::from(env::temp_dir())
            .join("libsodium_build")
            .join(&target);

        effective_install_dir = fallback_root.join("installed");
        effective_source_dir = fallback_root.join("source");

        println!(
            "cargo:warning=표준 빌드 경로에 공백이 있어 임시 경로를 사용합니다: {}",
            fallback_root.display()
        );
    }

    // 매 빌드마다 깨끗한 상태를 보장한다.
    let _ = fs::remove_dir_all(&effective_install_dir);
    let _ = fs::remove_dir_all(&effective_source_dir);

    fs::create_dir_all(&effective_install_dir)
        .map_err(|e| format!("설치 디렉터리 생성 실패 [{}]: {e}", effective_install_dir.display()))?;
    fs::create_dir_all(&effective_source_dir)
        .map_err(|e| format!("소스 디렉터리 생성 실패 [{}]: {e}", effective_source_dir.display()))?;

    if let Ok(source_dir_env) = env::var("SODIUM_SOURCE_DIR")
    {
        let candidate = PathBuf::from(source_dir_env);
        if !candidate.exists()
        {
            return Err(format!(
                "SODIUM_SOURCE_DIR 가 가리키는 경로가 존재하지 않습니다: {}",
                candidate.display()
            ));
        }
        source_root = find_source_root(&candidate)?;
    }
    else
    {
        // 로컬 압축 파일만 사용한다. 네트워크 다운로드는 하지 않는다.
        let archive_bin = retrieve_and_verify_archive("LATEST.tar.gz", "LATEST.tar.gz.minisig")?;
        source_root = build_source_archive_to_dir(archive_bin, &effective_source_dir)?;
    }

    let lib_dir = build_libsodium_from_source(&target, &source_root, &effective_install_dir)?;

    let link_name = if target.contains("msvc")
    {
        "libsodium"
    }
    else
    {
        "sodium"
    };

    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    println!("cargo:rustc-link-lib=static={}", link_name);

    let include_dir = source_root.join("src/libsodium/include");
    println!("cargo:include={}", include_dir.display());
    println!("cargo:lib={}", lib_dir.display());

    Ok(())
}

fn main()
{
    println!("cargo:rerun-if-env-changed=SODIUM_SOURCE_DIR");
    println!("cargo:rerun-if-env-changed=SODIUM_DIST_DIR");
    println!("cargo:rerun-if-env-changed=NUM_JOBS");
    println!("cargo:rerun-if-env-changed=CARGO_BUILD_JOBS");
    println!("cargo:rerun-if-changed=LATEST.tar.gz");
    println!("cargo:rerun-if-changed=LATEST.tar.gz.minisig");

    let res = install_from_source();

    if let Err(e) = res
    {
        panic!("libsodium build failed: {}", e);
    }
}