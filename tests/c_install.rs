//! `make install` as a C user runs it: the installed files, the soname, and
//! the example built through pkg-config and CMake, linked both shared and
//! static, then `make uninstall`. Linux only; skipped without make, a C
//! compiler or pkg-config, and the CMake part without cmake.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn have(tool: &str) -> bool {
    Command::new(tool).arg("--version").output().is_ok_and(|o| o.status.success())
}

fn run(cmd: &mut Command) -> Output {
    let out = cmd.output().unwrap_or_else(|e| panic!("{cmd:?}: {e}"));
    assert!(
        out.status.success(),
        "{cmd:?} failed\n{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

fn text(out: Output) -> String {
    String::from_utf8(out.stdout).unwrap()
}

fn make(target: &str, prefix: &Path) -> Output {
    run(Command::new("make")
        .arg(target)
        .arg(format!("PREFIX={}", prefix.display()))
        .args(["PROFILE=dev", "TARGET_DIR=target/c-install/build", "CARGO_FLAGS=--offline"])
        .current_dir(root()))
}

/// An ST 0601 packet with tags 2 (Precision Time Stamp, the ST 0601
/// section 8 example value) and 3 (Mission ID), and the tag 1 checksum.
fn packet(mission: &[u8]) -> Vec<u8> {
    let mut body = vec![2, 8, 0x00, 0x04, 0x59, 0xF4, 0xA6, 0xAA, 0x4A, 0xA8, 3, mission.len() as u8];
    body.extend_from_slice(mission);
    body.extend([1, 2]);
    let mut out = misb::st0601::KEY.to_vec();
    out.push((body.len() + 2) as u8);
    out.extend(&body);
    let sum = misb::checksum::st0601_checksum(&out);
    out.extend(sum.to_be_bytes());
    out
}

/// Two packets with a little damage between them, and what misb_dump
/// prints for them.
fn sample(dir: &Path) -> (PathBuf, String) {
    let (a, b) = (packet(b"MISSION01"), packet(b"MISSION02"));
    let sum = |p: &[u8]| u16::from_be_bytes([p[p.len() - 2], p[p.len() - 1]]);
    let expected = format!(
        "packet 1: ST 0601 UAS Datalink Local Set, checksum ok, 3 items\n\
         \x20   2 Precision Time Stamp: 2008-10-24T00:13:29.913000 MISP\n\
         \x20   3 Mission ID: \"MISSION01\"\n\
         \x20   1 Checksum: {}\n\
         packet 2: ST 0601 UAS Datalink Local Set, checksum ok, 3 items\n\
         \x20   2 Precision Time Stamp: 2008-10-24T00:13:29.913000 MISP\n\
         \x20   3 Mission ID: \"MISSION02\"\n\
         \x20   1 Checksum: {}\n",
        sum(&a),
        sum(&b)
    );
    let mut data = a;
    data.extend([0x00, 0xFF, 0x06]);
    data.extend(b);
    let path = dir.join("sample.klv");
    std::fs::write(&path, data).unwrap();
    (path, expected)
}

fn needed_libraries(exe: &Path) -> Option<String> {
    let out = Command::new("readelf").arg("-d").arg(exe).output().ok()?;
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

#[test]
fn install_then_build_with_pkg_config_and_cmake() {
    if !cfg!(target_os = "linux") {
        eprintln!("skipping: the layout checked here is Linux's");
        return;
    }
    for tool in ["make", "cc", "pkg-config"] {
        if !have(tool) {
            eprintln!("skipping: no {tool}");
            return;
        }
    }
    let work = root().join(format!("target/c-install/run-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).unwrap();
    let prefix = work.join("prefix");
    let lib = prefix.join("lib");
    make("install", &prefix);

    // Layout.
    for file in [
        "lib/libmisb.so.1",
        "lib/libmisb.a",
        "include/misb.h",
        "lib/pkgconfig/misb.pc",
        "lib/cmake/misb/misb-config.cmake",
        "lib/cmake/misb/misb-config-version.cmake",
    ] {
        assert!(prefix.join(file).is_file(), "{file} not installed");
    }
    assert_eq!(std::fs::read_link(lib.join("libmisb.so")).unwrap(), Path::new("libmisb.so.1"));
    assert_eq!(
        std::fs::read(prefix.join("include/misb.h")).unwrap(),
        std::fs::read(root().join("include/misb.h")).unwrap()
    );
    if let Some(dynamic) = needed_libraries(&lib.join("libmisb.so.1")) {
        assert!(dynamic.contains("Library soname: [libmisb.so.1]"), "{dynamic}");
    }

    let (input, expected) = sample(&work);
    let pkg_config = |args: &[&str]| -> Vec<String> {
        let out = run(Command::new("pkg-config").args(args).arg("misb").env("PKG_CONFIG_PATH", lib.join("pkgconfig")));
        text(out).split_whitespace().map(String::from).collect()
    };
    assert_eq!(pkg_config(&["--modversion"]), [env!("CARGO_PKG_VERSION")]);
    let example = root().join("examples/c/misb_dump.c");

    // Shared, through pkg-config.
    let shared = work.join("misb_dump_shared");
    run(Command::new("cc")
        .args(["-std=c99", "-Wall", "-Wextra", "-Werror"])
        .arg(&example)
        .args(pkg_config(&["--cflags", "--libs"]))
        .arg("-o")
        .arg(&shared));
    let out = text(run(Command::new(&shared).arg(&input).env("LD_LIBRARY_PATH", &lib)));
    assert_eq!(out, expected);
    if let Some(dynamic) = needed_libraries(&shared) {
        assert!(dynamic.contains("[libmisb.so.1]"), "linked by soname: {dynamic}");
    }
    let empty = run(Command::new(&shared).arg("/dev/null").env("LD_LIBRARY_PATH", &lib));
    assert!(empty.stdout.is_empty());

    // Static, with the system libraries pkg-config lists for it.
    let fixed = work.join("misb_dump_static");
    let system_libs: Vec<String> =
        pkg_config(&["--static", "--libs-only-l"]).into_iter().filter(|l| l != "-lmisb").collect();
    assert!(!system_libs.is_empty(), "Libs.private is empty");
    run(Command::new("cc")
        .args(["-std=c99", "-Wall", "-Wextra", "-Werror"])
        .args(pkg_config(&["--cflags"]))
        .arg(&example)
        .arg(lib.join("libmisb.a"))
        .args(&system_libs)
        .arg("-o")
        .arg(&fixed));
    assert_eq!(text(run(Command::new(&fixed).arg(&input))), expected);
    if let Some(dynamic) = needed_libraries(&fixed) {
        assert!(!dynamic.contains("libmisb"), "static build still needs libmisb: {dynamic}");
    }

    // CMake: find_package, both targets, and the version check.
    if have("cmake") {
        for (static_link, name) in [("OFF", "cmake-shared"), ("ON", "cmake-static")] {
            let build = work.join(name);
            run(Command::new("cmake")
                .arg("-S")
                .arg(root().join("examples/c"))
                .arg("-B")
                .arg(&build)
                .arg(format!("-DCMAKE_PREFIX_PATH={}", prefix.display()))
                .arg(format!("-DMISB_STATIC={static_link}")));
            run(Command::new("cmake").arg("--build").arg(&build));
            let exe = build.join("misb_dump");
            assert_eq!(text(run(Command::new(&exe).arg(&input))), expected, "{name}");
            assert!(run(Command::new(&exe).arg("/dev/null")).stdout.is_empty(), "{name}");
        }
        let project = work.join("needs-newer");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(
            project.join("CMakeLists.txt"),
            "cmake_minimum_required(VERSION 3.10)\nproject(t C)\nfind_package(misb 0.2 REQUIRED)\n",
        )
        .unwrap();
        let refused = Command::new("cmake")
            .arg("-S")
            .arg(&project)
            .arg("-B")
            .arg(project.join("build"))
            .arg(format!("-DCMAKE_PREFIX_PATH={}", prefix.display()))
            .output()
            .unwrap();
        let why = String::from_utf8_lossy(&refused.stderr);
        assert!(!refused.status.success(), "0.1 must not satisfy a request for 0.2");
        assert!(why.contains("considered but not accepted") && why.contains("version: 0.1.0"), "{why}");
    } else {
        eprintln!("skipping the CMake part: no cmake");
    }

    // Uninstall leaves no files behind.
    make("uninstall", &prefix);
    let mut left = Vec::new();
    let mut stack = vec![prefix.clone()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
            } else {
                left.push(path);
            }
        }
    }
    assert!(left.is_empty(), "left after uninstall: {left:?}");
    let _ = std::fs::remove_dir_all(&work);
}
