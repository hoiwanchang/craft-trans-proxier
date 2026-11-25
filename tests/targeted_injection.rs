//! Acceptance test for "inject only the whitelisted programs" — WRITTEN BUT NOT YET PASSING.
//!
//! Status: `#[ignore]`d because the run does not finish inside 60 s. That is not a test
//! flake to paper over: the phases before it (snapshot, remote LoadLibrary, module
//! verify) each have a bounded wait, so something in the chain blocks far longer than it
//! should. Until that is found, the narrow-injection claim is UNVERIFIED end to end —
//! only its parts are (see `src/inject.rs` tests: the snapshot names processes, the
//! module walk works, and a remote thread really does load the DLL into a process).
//!
//! To investigate: run with `--nocapture`, and time `Engine::start`, the watcher's first
//! pass, and `drop(engine)` separately. Prime suspects are the 1.5 s teardown wait
//! combined with `Watcher::shutdown` joining a poll loop that is itself inside a
//! 5-second `WaitForSingleObject`, and `servers.shutdown()` blocking on a relay whose
//! accept loop outlives the stop flag.
//!
//! If the finding turns out to be "injecting a GUI process makes it wait", that is a
//! product bug, not a test bug: an injector must not stall the target it enters.

#![cfg(windows)]

use std::process::{Child, Command, Stdio};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use trans_proxier::config::Config;
use trans_proxier::inject;
use trans_proxier::intercept;
use trans_proxier::monitor::Monitor;

/// Subjects must not inherit the harness's captured stdout: a child holding that pipe
/// open keeps the test "running" until it exits.
fn detached(mut cmd: Command) -> std::io::Result<Child> {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
}

fn spawn(exe: &str) -> Option<Child> {
    detached(Command::new(exe)).ok()
}

fn dll_of_target_dir() -> String {
    let mut d = std::env::current_exe().expect("exe");
    d.pop();
    if !d.join("tpdrv.dll").exists() {
        d.pop();
    }
    d.join("tpdrv.dll").to_string_lossy().to_string()
}

fn until(deadline: Duration, cond: impl Fn() -> bool) -> bool {
    let t = Instant::now();
    while t.elapsed() < deadline {
        if cond() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    false
}

#[test]
#[ignore = "does not complete in 60 s: the narrow-injection claim is not yet verified \
            end to end, and an injector must not stall its target — investigate, do not un-ignore"]
fn only_the_whitelisted_image_ever_sees_the_dll() {
    let dll = dll_of_target_dir();
    assert!(std::path::Path::new(&dll).exists(), "build tpdrv.dll first: {dll}");

    // Two images that both exist on Windows 11 and both stay alive while we look:
    // charmap (listed) and a 61-echo ping (unlisted). eudc.exe, the first choice, is
    // gone on this OS, and a subject that already exited would make "not injected"
    // pass for the wrong reason — hence the liveness assert below.
    const LISTED: &str = "charmap.exe";
    const UNLISTED: &str = "ping.exe";

    let mut cfg = Config::default();
    cfg.settings.app_whitelist_enabled = true;
    cfg.settings.app_whitelist = vec![LISTED.to_string()];

    let mut subject_listed = spawn(LISTED).expect("start the listed subject");
    let mut c = Command::new(UNLISTED);
    c.args(["-n", "61", "127.0.0.1"]);
    let mut subject_other = detached(c).expect("start the unlisted subject");
    std::thread::sleep(Duration::from_millis(600));

    let t = Instant::now();
    let engine = intercept::Engine::start(
        Arc::new(RwLock::new(cfg)),
        Arc::new(Monitor::new()),
        &dll,
    )
    .expect("engine should start in targeted mode");
    println!("engine started in {:?}", t.elapsed());

    let t = Instant::now();
    let got_in = until(Duration::from_secs(10), || {
        inject::module_loaded(subject_listed.id(), "tpdrv.dll")
    });
    println!("listed injected: {got_in} after {:?}", t.elapsed());

    std::thread::sleep(Duration::from_millis(2500));
    let other_touched = inject::module_loaded(subject_other.id(), "tpdrv.dll");
    let other_alive = subject_other.try_wait().ok().flatten().is_none();

    let t = Instant::now();
    drop(engine);
    println!("engine dropped in {:?}", t.elapsed());

    let _ = subject_listed.kill();
    let _ = subject_other.kill();

    assert!(got_in, "the whitelisted {LISTED} was never injected");
    assert!(other_alive, "negative case is vacuous: the subject already exited");
    assert!(
        !other_touched,
        "{UNLISTED} carries tpdrv.dll although the profile never named it"
    );
}
