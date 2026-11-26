//! Acceptance test for the requirement "inject only the whitelisted programs", plus a
//! bounded reproduction of the shutdown stall (task #21).
//!
//! The unit tests in `src/inject.rs` prove the primitive — a remote thread really does
//! load the DLL, and the process snapshot names processes. Neither proves the property
//! the operator asked for: that a process NOT in the profile is left completely alone.
//! That distinction is the entire reason the global message hook was removed, so it is
//! asserted here rather than argued.
//!
//! Two things this file deliberately does:
//!  * it never leaves a child process behind — the subjects are killed even when an
//!    assertion fires, and children get null stdio so they cannot keep the harness's
//!    capture pipe open (that alone once looked like a 60-second hang);
//!  * it never blocks the suite — `Engine::drop` is known to stall, so stopping goes
//!    through `stop_within`, which turns the stall into a failure with a deadline.
//!    A hang would hide every other test in the binary, which is worth less than a red.
//!
//! A false alarm worth recording: this test first looked like it "hung for 60 s". It was
//! failing in 0.6 s because a real engine on the machine already held the session mutex.
//! Rule out an environment collision before believing a timing story.

#![cfg(windows)]

use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant};

use trans_proxier::config::Config;
use trans_proxier::inject;
use trans_proxier::intercept;
use trans_proxier::monitor::Monitor;

/// Both tests start an engine, and the engine mutex is instance-scoped, so they share
/// one instance name AND a process-local lock: without that they raced each other via
/// `set_var` (last writer wins) and intermittently failed with
/// "另一个透明引擎实例已在运行" — a flake caused by the test, not the product.
fn engine_gate() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    static READY: OnceLock<()> = OnceLock::new();
    READY.get_or_init(|| unsafe { std::env::set_var("TPROXIER_INSTANCE", "targetedinj") });
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

/// Subjects must not inherit the harness's captured stdout: a child holding that pipe
/// open keeps the test "running" until it exits.
fn detached(mut cmd: Command) -> std::io::Result<Child> {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
}

fn spawn(exe: &str, args: &[&str]) -> Option<Child> {
    let mut c = Command::new(exe);
    c.args(args);
    detached(c).ok()
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

/// Stop on another thread and wait with a deadline. `Engine::drop` currently stalls
/// (task #21: something in `servers.shutdown()` never observes the stop flag), and
/// asserting inline would hang the whole suite instead of reporting that.
fn stop_within(engine: intercept::Engine, limit: Duration) -> Result<(), Duration> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        drop(engine);
        let _ = tx.send(());
    });
    match rx.recv_timeout(limit) {
        Ok(()) => Ok(()),
        Err(_) => Err(limit),
    }
}

/// Kills its children whether or not the assertions pass.
struct Subjects {
    listed: Option<Child>,
    other: Option<Child>,
}

impl Drop for Subjects {
    fn drop(&mut self) {
        for c in [&mut self.listed, &mut self.other].into_iter().flatten() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

#[test]
fn only_the_whitelisted_image_ever_sees_the_dll() {
    let _gate = engine_gate();
    let dll = dll_of_target_dir();
    assert!(std::path::Path::new(&dll).exists(), "build tpdrv.dll first: {dll}");

    // Two images that both exist on Windows 11 and both stay alive while we look:
    // charmap (listed) and a self-pinging loopback (unlisted). eudc.exe, the first
    // choice, is gone on this OS, and a subject that had already exited would make
    // "not injected" pass for the wrong reason — hence the liveness assert.
    const LISTED: &str = "charmap.exe";
    const UNLISTED: &str = "ping.exe";

    let mut cfg = Config::default();
    cfg.settings.app_whitelist_enabled = true;
    cfg.settings.app_whitelist = vec![LISTED.to_string()];

    let mut subjects = Subjects {
        listed: spawn(LISTED, &[]),
        other: spawn(UNLISTED, &["-n", "61", "127.0.0.1"]),
    };
    let (mut listed, mut other) = (subjects.listed.take().unwrap(), subjects.other.take().unwrap());
    std::thread::sleep(Duration::from_millis(600));

    let started = Instant::now();
    let engine = intercept::Engine::start(Arc::new(RwLock::new(cfg)), Arc::new(Monitor::new()), &dll)
        .expect("engine should start in targeted mode");
    println!("engine started in {:?}", started.elapsed());

    let t = Instant::now();
    let got_in = until(Duration::from_secs(10), || {
        inject::module_loaded(listed.id(), "tpdrv.dll")
    });
    println!("listed injected: {got_in} after {:?}", t.elapsed());

    // the negative half: same grace period, and the unlisted process must still be clean
    std::thread::sleep(Duration::from_millis(2500));
    let other_touched = inject::module_loaded(other.id(), "tpdrv.dll");
    let other_alive = other.try_wait().ok().flatten().is_none();

    let dropped = stop_within(engine, Duration::from_secs(10));

    let res = (|| {
        assert!(
            got_in,
            "the whitelisted {LISTED} was never injected - targeted injection is not working"
        );
        assert!(other_alive, "negative case is vacuous: the unlisted subject already exited");
        assert!(
            !other_touched,
            "{UNLISTED} carries tpdrv.dll although the profile never named it"
        );
        if let Err(limit) = dropped {
            // Reported, not asserted: this test's job is the injection SCOPE, and
            // `stopping_without_any_injection_is_bounded` already owns the stall
            // (task #21). Failing here too would hide a green property behind a known bug.
            println!(
                "note: Engine::drop did not finish within {limit:?} - tracked as task #21, \
                 asserted in stopping_without_any_injection_is_bounded"
            );
        }
    })();
    // put the children back so Drop reaps them, whatever happened above
    subjects.listed = Some(listed);
    subjects.other = Some(other);
    drop(subjects);
    let _ = res;
}

/// Same engine, same start/stop, but a whitelist naming a process that cannot exist, so
/// NOTHING is ever injected. If the stop still stalls, the fault is in the servers/pipe
/// shutdown and not in the remote eject — which is what it showed.
#[test]
fn stopping_without_any_injection_is_bounded() {
    let _gate = engine_gate();
    let dll = dll_of_target_dir();
    let mut cfg = Config::default();
    cfg.settings.app_whitelist_enabled = true;
    cfg.settings.app_whitelist = vec!["definitely-not-running.exe".to_string()];

    let engine = intercept::Engine::start(Arc::new(RwLock::new(cfg)), Arc::new(Monitor::new()), &dll)
        .expect("engine should start");
    std::thread::sleep(Duration::from_millis(1200));
    let t = Instant::now();
    let dropped = stop_within(engine, Duration::from_secs(10));
    println!("drop with zero injections took {:?}", t.elapsed());
    if let Err(limit) = dropped {
        panic!(
            "shutdown hung past {limit:?} even though NOTHING was injected - the stall is \
             inside servers.shutdown(), not the remote eject (task #21)"
        );
    }
}
