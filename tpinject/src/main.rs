//! `tpinject` — command-line host for the transparent-interception engine (the
//! same `trans_proxier::intercept::Engine` the desktop GUI's 启动 button uses).
//! Useful for headless service operation / the cross-process integration test.
#![allow(non_snake_case)]

#[cfg(not(windows))]
compile_error!("tpinject builds only for a *-pc-windows-* target");

use std::path::Path;
use std::sync::{Arc, RwLock};

use trans_proxier::config::Config;
use trans_proxier::intercept::Engine;
use trans_proxier::monitor::Monitor;
#[cfg(windows)]
use trans_proxier::wfp::Wfp;

struct Args {
    config: String,
    driver: String,
    preview: bool,
    consent_hook: bool,
    wfp_preview: bool,
    /// Arm the WFP kernel redirect alongside the hook. This is the headless host, and
    /// the kernel route exists for exactly what a message hook cannot reach: services,
    /// console apps with no message pump, and processes started before the hook.
    wfp: bool,
    consent_wfp: bool,
    /// Run WITHOUT the global message hook at all: the WFP kernel route covers the
    /// processes a message hook cannot (services, console apps with no message pump,
    /// anything started before install), so a headless kernel-route host must be able to
    /// exist without touching other processes' address spaces.
    no_hook: bool,
}

fn parse_args() -> Args {
    let argv: Vec<String> = std::env::args().collect();
    let mut a = Args {
        config: "Settings.ini".into(),
        driver: "tpdrv.dll".into(),
        preview: false,
        consent_hook: false,
        wfp_preview: false,
        wfp: false,
        consent_wfp: false,
        no_hook: false,
    };
    let mut i = 1;
    while i < argv.len() {
        match argv[i].as_str() {
            "--config" => {
                i += 1;
                a.config = argv.get(i).cloned().unwrap_or_default();
            }
            "--driver" => {
                i += 1;
                a.driver = argv.get(i).cloned().unwrap_or_default();
            }
            "--preview" => a.preview = true,
            "--wfp-preview" => a.wfp_preview = true,
            "--wfp" => a.wfp = true,
            "--i-consent-to-install-wfp-filters" => a.consent_wfp = true,
            "--no-hook" => a.no_hook = true,
            "--i-consent-to-install-global-hook" => a.consent_hook = true,
            _ => {}
        }
        i += 1;
    }
    a
}

/// Print any new monitor lines to stdout as they arrive (so a test harness can
/// observe interceptions cross-process).
fn drain_lines(monitor: &Monitor, cursor: &mut u64) {
    let (lines, c) = monitor.since(*cursor);
    *cursor = c;
    for l in lines {
        println!("[{}] {} {}", l.time, l.level, l.message);
    }
}

fn main() {
    let args = parse_args();

    // CONSENT GATE: installing a global message hook affects EVERY GUI process in
    // the session, so it is checked here — before the profile is even read — so that
    // refusing never depends on any other argument being valid. The two previews are the
    // no-consent escape hatch and are therefore excluded.
    // the session (this already once leaked tpdrv.dll into the user's apps), so it
    // must be an explicit choice, never the default.
    if !args.preview && !args.wfp_preview && !args.no_hook && !args.consent_hook {
        eprintln!(
            "tpinject refuses to install a GLOBAL hook without consent.\n\
             This loads the hook DLL into every message-pumping app in your session.\n\
             Re-run with --i-consent-to-install-global-hook to proceed, or use\n\
             --preview / --wfp-preview to see what it WOULD do."
        );
        std::process::exit(3);
    }

    // A hookless run that also does not arm the kernel route would intercept nothing at
    // all — say so rather than idle forever looking like a running proxy.
    if !args.preview && !args.wfp_preview && args.no_hook && !args.wfp {
        eprintln!(
            "tpinject --no-hook without --wfp would proxify nothing: the hook is what the\n\
             driverless path uses, and --wfp is the kernel path. Pass one of them."
        );
        std::process::exit(3);
    }

    let config = match Config::load(Path::new(&args.config)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("tpinject: {e}");
            std::process::exit(1);
        }
    };

    // Safe, side-effect-free previews.
    if args.wfp_preview {
        println!("WFP connect-redirect preview (NO filters installed):");
        println!("  a filter alone cannot redirect: FWPM_ACTION0 has no endpoint field,");
        println!("  so each filter hands the flow to our callout (needs the .sys driver).");
        let mut any = false;
        for app in &config.settings.app_whitelist {
            if app.trim().is_empty() {
                continue;
            }
            any = true;
            // one filter per transport, as the real install does
            for proto in [trans_proxier::wfp::IPPROTO_TCP, trans_proxier::wfp::IPPROTO_UDP] {
                println!("  {}", Wfp::preview_route(app.trim(), false, proto));
            }
        }
        if !any {
            println!("  (whitelist empty — enable 程序白名单 and list programs)");
        }
        return;
    }

    if args.preview {
        println!("DRY RUN: would start the transparent engine with driver={}", args.driver);
        println!("  (no global hook installed; add --i-consent-to-install-global-hook to actually install)");
        return;
    }


    let config = Arc::new(RwLock::new(config));
    let monitor = Arc::new(Monitor::new());

    // ── WFP kernel route ───────────────────────────────────────────────────────
    // prepare() must run BEFORE the engine binds its listeners: spawn_servers only
    // creates the TCP/UDP token ports when the ingress path is already latched, and
    // commit() must run after them because the driver cannot be handed a pool that
    // does not exist yet. Same two-phase shape the GUI uses (src/wfp_route.rs).
    #[cfg(windows)]
    let wfp_ready = if args.wfp {
        if !args.consent_wfp {
            eprintln!(
                "tpinject --wfp refuses to install WFP filters without consent: they change \n\
                 real routing for every whitelisted program. Re-run with                 \n\
                 --i-consent-to-install-wfp-filters."
            );
            std::process::exit(3);
        }
        let snapshot = config.read().unwrap().clone();
        match trans_proxier::wfp_route::prepare(&snapshot, true) {
            Ok(()) => true,
            Err(e) => {
                eprintln!("tpinject: WFP route not armed: {e}");
                std::process::exit(4);
            }
        }
    } else {
        false
    };
    #[cfg(not(windows))]
    let wfp_ready = false;
    let cfg_snapshot = config.read().unwrap().clone();

    let mut tpinject_route: Option<trans_proxier::wfp_route::Route> = None;
    // Held for the whole run: dropping it is what tears the route (or the hook) down.
    let mut servers = None;
    if args.no_hook {
        match trans_proxier::intercept::spawn_servers(config.clone(), monitor.clone()) {
            Ok(s) => servers = Some(s),
            Err(e) => {
                eprintln!("tpinject: engine listeners failed: {e}");
                std::process::exit(2);
            }
        }
        println!("tpinject: running hookless (WFP kernel route only, no global message hook)");
        Ok(())
    } else {
        Engine::start(config, monitor.clone(), &args.driver).map(|_| ())
    }
    .map(|_engine| {
            if wfp_ready {
                match trans_proxier::wfp_route::commit(&cfg_snapshot, &monitor) {
                    // held for the rest of the process: dropping it disarms the driver
                    Ok(route) => {
                        println!("tpinject: WFP route armed ({} redirect filters)", route.installed());
                        tpinject_route = Some(route);
                    }
                    Err(e) => eprintln!("tpinject: WFP filters could not be installed: {e}"),
                }
            }
        })
    .map_err(|e| {
        eprintln!("tpinject: {e}");
        std::process::exit(2);
    })
    .ok();
    let _ = servers;

    let mut cursor = 0u64;
    let mut seen = None;
    loop {
        drain_lines(&monitor, &mut cursor);
        // A callout driver that is stopped and started again comes back INERT, which
        // looks exactly like "nothing matches" from the outside. Poll and re-arm.
        #[cfg(windows)]
        if tpinject_route.is_some() {
            match trans_proxier::wfp_ingress::ensure_armed() {
                Ok(st) => {
                    if seen != Some(st) {
                        println!(
                            "tpinject: driver enabled={} tcp={} udp={} untrackable={}",
                            st.enabled, st.token_count, st.udp_token_count, st.udp_untrackable
                        );
                        seen = Some(st);
                    }
                }
                Err(e) => eprintln!("tpinject: driver status unavailable: {e}"),
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(300));
    }
}
