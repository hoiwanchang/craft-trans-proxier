use crate::check;
use crate::config::Config;
use crate::engine;
use crate::profiles::ProfileStore;
use crate::rules::{decide_route, Decision};
use std::path::{Path, PathBuf};
use std::time::Duration;

const DEFAULT_CONFIG: &str = "Settings.ini";

struct Args {
    cmd: String,
    config: PathBuf,
    positional: Vec<String>,
    host: Option<String>,
    port: Option<u16>,
    app: Option<String>,
    proto: Option<String>,
    socks5: Option<String>,
    chain: Option<u32>,
    proxy: Option<u32>,
    apply: bool,
    once: bool,
    verify: bool,
    consent_wfp: bool,
    /// passed by the logon (HKCU Run) entry: start in the tray, no window
    minimised: bool,
}

fn parse_args(argv: Vec<String>) -> Result<Args, String> {
    let mut a = Args {
        cmd: String::new(),
        config: PathBuf::from(DEFAULT_CONFIG),
        positional: Vec::new(),
        host: None,
        port: None,
        app: None,
        proto: None,
        socks5: None,
        chain: None,
        proxy: None,
        apply: false,
        once: false,
        verify: false,
        consent_wfp: false,
        minimised: false,
    };
    let mut rest = argv;
    // argv[0] is the program path; argv[1] is the command (or nothing, or flags)
    if rest.len() < 2 {
        // No command at all — default to the GUI
        a.cmd = "gui".into();
        rest.clear();
    } else {
        let first = rest[1].as_str();
        if first == "--help" || first == "-h" || first == "help" {
            a.cmd = "help".into();
            rest.clear();
        } else if first.starts_with('-') {
            // Flags only — go to the GUI
            a.cmd = "gui".into();
            rest.remove(0);
        } else {
            a.cmd = rest[1].clone();
            rest.remove(0);
            rest.remove(0);
        }
    }
    let mut i = 0;
    while i < rest.len() {
        let tok = rest[i].as_str();
        match tok {
            "--config" => {
                i += 1;
                a.config = PathBuf::from(rest.get(i).ok_or("--config requires a path")?);
            }
            "--host" => {
                i += 1;
                a.host = Some(rest.get(i).ok_or("--host requires a value")? .clone());
            }
            "--port" => {
                i += 1;
                a.port = Some(
                    rest.get(i)
                        .ok_or("--port requires a value")?
                        .parse::<u16>()
                        .map_err(|_| "invalid --port")?,
                );
            }
            "--app" => {
                i += 1;
                a.app = Some(rest.get(i).ok_or("--app requires a value")? .clone());
            }
            "--proto" => {
                i += 1;
                a.proto = Some(rest.get(i).ok_or("--proto requires a value")?.clone());
            }
            "--chain" => {
                i += 1;
                a.chain = Some(
                    rest.get(i)
                        .ok_or("--chain requires a value")?
                        .parse::<u32>()
                        .map_err(|_| "invalid --chain")?,
                );
            }
            "--proxy" => {
                i += 1;
                a.proxy = Some(
                    rest.get(i)
                        .ok_or("--proxy requires a value")?
                        .parse::<u32>()
                        .map_err(|_| "invalid --proxy")?,
                );
            }
            "--socks5" => {
                i += 1;
                a.socks5 = Some(rest.get(i).ok_or("--socks5 requires host:port")? .clone());
            }
            "--apply" => a.apply = true,
            "--verify" => a.verify = true,
            "--once" => a.once = true,
            // what the logon entry passes; unknown flags otherwise fall into `positional`,
            // which would make autostart silently open a window instead of the tray
            "--minimised" => a.minimised = true,
            "--i-consent-to-install-wfp-filters" => a.consent_wfp = true,
            "--help" | "-h" => {
                return Err("help".into());
            }
            other => a.positional.push(other.to_string()),
        }
        i += 1;
    }
    Ok(a)
}

/// `trans-proxier autostart install|remove|status` — the per-user logon entry.
///
/// `install` reads the registry back and compares before claiming success: a return code
/// alone says the write call was accepted, not that the machine will now do what you
/// think it will, and this is the kind of setting whose failure only shows up at next
/// boot — when nobody is watching.
fn cmd_autostart(args: &Args) -> u8 {
    #[cfg(windows)]
    {
        use crate::autostart;
        let exe = std::env::current_exe()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|_| "trans-proxier.exe".into());
        match args.positional.first().map(|s| s.as_str()).unwrap_or("") {
            "install" => match autostart::install(&exe) {
                Ok(cmd) => match autostart::status() {
                    Ok(Some(v)) if v == cmd => {
                        println!("registered at logon and verified: {v}");
                        0
                    }
                    other => {
                        eprintln!("warning: written, but read-back does not match: {other:?}");
                        1
                    }
                },
                Err(e) => {
                    eprintln!("error: {e}");
                    1
                }
            },
            "remove" => match autostart::remove() {
                Ok(()) => {
                    println!("removed; registry now holds {:?}", autostart::status().ok().flatten());
                    0
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    1
                }
            },
            "status" => match autostart::status() {
                Ok(Some(v)) => {
                    println!("enabled: {v}");
                    0
                }
                Ok(None) => {
                    println!("not registered (the app runs only when you start it)");
                    0
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    1
                }
            },
            other => {
                eprintln!("usage: trans-proxier autostart install|remove|status");
                if !other.is_empty() {
                    eprintln!("       unknown argument: {other}");
                }
                2
            }
        }
    }
    #[cfg(not(windows))]
    {
        let _ = args;
        eprintln!("error: the logon entry is Windows-only");
        1
    }
}

const USAGE: &str = "\
trans-proxier — clean-room transparent proxy engine (Rust)

Usage:
  trans-proxier                            Open the GUI (default)
  trans-proxier --minimised                 Open hidden in the tray (what logon uses)
  trans-proxier autostart install|remove|status
                                            Register / clear / show the per-user logon entry
  trans-proxier gui                        Open the GUI
  trans-proxier init                       Write a sample Settings.ini
  trans-proxier validate                   Check the config file
  trans-proxier list                       Show the config (settings, proxies, chains, rules)
  trans-proxier check --proxy <id>          Test a single proxy (default target: example.com:443)
  trans-proxier check --chain <id>          Test a chain (default target: example.com:443)
  trans-proxier wfp [--apply --once] [--i-consent-to-install-wfp-filters]
                                       Preview / install the WFP connect-redirect route
  trans-proxier wfp --verify
                                       End-to-end acceptance gate for the WFP route (read-only)
  trans-proxier route <host> <port>        Show what the rule engine would do for a connection
                                           (optionally --app NAME --proto tcp|udp)
  trans-proxier serve --socks5 H:P         Start a local SOCKS5 proxy honoring the config

Flags:
  --config <path>   Config file (default: Settings.ini)
  --host <h>       target host (default: example.com)
  --port <p>       target port (default: 443)
  --app <name>     app name used for rule matching (serve/route)
  --proto <p>      connection protocol for route: tcp | udp | any (default any)

profiles <list|new <n>|save <n>|load <n>|delete <n>|rename <a> <b>|import <file> <n>|export <n> <file>>
                   manage profiles in <config-dir>/profiles (fnd_13 Profiles)
";

pub fn run(argv: Vec<String>) -> u8 {
    let args = match parse_args(argv) {
        Ok(a) => a,
        Err(e) if e == "help" => {
            eprintln!("{USAGE}");
            return 0;
        }
        Err(e) => {
            eprintln!("error: {e}\n{USAGE}");
            return 2;
        }
    };

    match args.cmd.as_str() {
        #[cfg(feature = "gui")]
        "gui" => cmd_gui(&args),
        #[cfg(not(feature = "gui"))]
        "gui" => {
            eprintln!("error: this build has no GUI (compiled without the `gui` feature)");
            1
        }
        "init" => cmd_init(&args),
        "validate" => cmd_validate(&args),
        "list" => cmd_list(&args),
        "check" => cmd_check(&args),
        "route" => cmd_route(&args),
        "serve" => cmd_serve(&args),
        "profiles" => cmd_profiles(&args),
        "autostart" => cmd_autostart(&args),
        "wfp" => cmd_wfp(&args),
        "--help" | "-h" | "help" => {
            eprintln!("{USAGE}");
            0
        }
        other => {
            eprintln!("error: unknown command \"{other}\"\n{USAGE}");
            2
        }
    }
}

fn load_config(args: &Args) -> Result<Config, u8> {
    let config = Config::load(&args.config).map_err(|e| {
        eprintln!("error: {e}");
        1u8
    })?;
    Ok(config)
}

#[cfg(feature = "gui")]
fn cmd_gui(args: &Args) -> u8 {
    crate::gui::run(args.config.clone(), args.minimised)
}

fn cmd_init(args: &Args) -> u8 {
    if args.config.exists() {
        eprintln!("error: {} already exists (refusing to overwrite)", args.config.display());
        return 1;
    }
    let mut cfg = Config::default();
    cfg.proxies.push(crate::config::ProxyServer {
        id: 1,
        name: "example-http".into(),
        kind: crate::config::ProxyKind::Http,
        host: "127.0.0.1".into(),
        port: 8080,
        username: Some("user".into()),
        password: Some("pass".into()),
        timeout_secs: 10,
    });
    cfg.chains.push(crate::config::Chain { id: 1, name: "example-chain".into(), proxies: vec![1] });
    cfg.rules.push(crate::config::Rule {
        id: 1,
        name: "all-apps-through-proxy".into(),
        enabled: true,
        priority: 10,
        app: None,
        host: None,
        port: None,
        protocol: crate::config::RuleProtocol::Both,
        action: crate::config::RuleAction::Proxy { chain: 1 },
    });
    if let Err(e) = cfg.write(&args.config) {
        eprintln!("error: {e}");
        return 1;
    }
    println!(
        "wrote {} with one example proxy, chain and rule — edit it to match your environment",
        args.config.display()
    );
    0
}

fn cmd_validate(args: &Args) -> u8 {
    let config = match load_config(args) {
        Ok(c) => c,
        Err(code) => return code,
    };
    let errors = config.validate();
    if errors.is_empty() {
        println!("config OK: {} ({} proxy(ies), {} chain(s), {} rule(s))",
            args.config.display(),
            config.proxies.len(),
            config.chains.len(),
            config.rules.len());
        0
    } else {
        println!("config INVALID: {}", args.config.display());
        for e in &errors {
            println!("  - {}", e.message);
        }
        1
    }
}

fn cmd_list(args: &Args) -> u8 {
    let config = match load_config(args) {
        Ok(c) => c,
        Err(code) => return code,
    };
    println!("settings: name=\"{}\" dns_mode={} ip_leak_prevention={} language={}",
        config.settings.name,
        config.settings.dns_mode.as_str(),
        config.settings.ip_leak_prevention,
        config.settings.language.as_str());
    println!("  exclusion_list: {}", config.settings.proxy_exclusion_list.join(", "));
    println!("  inclusion_list: {}", config.settings.proxy_inclusion_list.join(", "));
    println!("  app_whitelist_enabled={}: {}", config.settings.app_whitelist_enabled, config.settings.app_whitelist.join(", "));
    println!("proxies:");
    for p in &config.proxies {
        println!("  #{} {} [{}] {}:{} (timeout {}s)", p.id, p.name, p.kind.as_str(), p.host, p.port, p.timeout_secs);
    }
    println!("chains:");
    for c in &config.chains {
        println!("  #{} {} -> proxies [{}]", c.id, c.name, c.proxies.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(", "));
    }
    println!("rules:");
    for r in &config.rules {
        let action = match &r.action {
            crate::config::RuleAction::Proxy { chain } => format!("proxy(chain={chain})"),
            crate::config::RuleAction::Direct => "direct".into(),
            crate::config::RuleAction::Block => "block".into(),
        };
        let proto = match r.protocol {
            crate::config::RuleProtocol::Tcp => "tcp",
            crate::config::RuleProtocol::Udp => "udp",
            crate::config::RuleProtocol::Both => "tcp+udp",
        };
        println!(
            "  #{} {} {} priority={} app={:?} host={:?} port={:?} proto={proto} action={}",
            r.id, r.name,
            if r.enabled { "on " } else { "off" },
            r.priority, r.app, r.host, r.port, action
        );
    }
    0
}

fn cmd_check(args: &Args) -> u8 {
    let config = match load_config(args) {
        Ok(c) => c,
        Err(code) => return code,
    };
    let host = args.host.clone().unwrap_or_else(|| "example.com".into());
    let port = args.port.unwrap_or(443);
    let timeout = Duration::from_secs(10);

    if let Some(id) = args.proxy {
        let proxy = match config.proxy_by_id(id) {
            Some(p) => p.clone(),
            None => {
                eprintln!("error: proxy #{id} not found in config");
                return 1;
            }
        };
        let result = check::check_proxy(&proxy, &host, port, timeout);
        print_check(&result);
        return if result.ok { 0 } else { 1 };
    }
    if let Some(id) = args.chain {
        if config.chain_by_id(id).is_none() {
            eprintln!("error: chain #{id} not found in config");
            return 1;
        }
        let result = check::check_chain(&config, id, &host, port);
        print_check(&result);
        return if result.ok { 0 } else { 1 };
    }
    eprintln!("error: provide --proxy <id> or --chain <id>");
    2
}

fn print_check(result: &check::CheckResult) {
    let mark = if result.ok { "PASS" } else { "FAIL" };
    println!("[{}] {} → {}:{}", mark, result.proxy_name, result.host, result.port);
    println!("      {}", result.message);
}

fn cmd_route(args: &Args) -> u8 {
    // Accept `route <host> <port>` OR `route --host H --port P` (the global flags
    // were advertised but only positional worked — a real usability bug).
    let host = if args.positional.len() >= 2 {
        args.positional[0].clone()
    } else {
        match &args.host {
            Some(h) => h.clone(),
            None => {
                eprintln!("error: `route <host> <port>` or `route --host H --port P` [--app NAME]");
                return 2;
            }
        }
    };
    let port: u16 = if args.positional.len() >= 2 {
        match args.positional[1].parse() {
            Ok(p) => p,
            Err(_) => {
                eprintln!("error: invalid port '{}'", args.positional[1]);
                return 2;
            }
        }
    } else {
        match args.port {
            Some(p) => p,
            None => {
                eprintln!("error: route needs a port (`--port P` or positional)");
                return 2;
            }
        }
    };
    let config = match load_config(args) {
        Ok(c) => c,
        Err(code) => return code,
    };
    let proto = match args.proto.as_deref().map(|s| s.to_ascii_lowercase()) {
        None => 0,
        Some(s) if s.is_empty() || s == "any" || s == "all" => 0,
        Some(s) if s == "tcp" => 6,
        Some(s) if s == "udp" => 17,
        Some(s) => {
            eprintln!("error: --proto must be tcp|udp|any (got '{s}')");
            return 2;
        }
    };
    let decision = decide_route(&config, args.app.as_deref(), &host, port, proto);
    match &decision {
        Decision::Proxy { chain, rule } => {
            // rule 0 means the DNS-through-proxy policy moved it, not the profile.
            let origin = if *rule == 0 { "DNS policy".to_string() } else { format!("rule #{rule}") };
            println!("route: via chain #{chain} ({origin})");
            let chain_obj = config.chain_by_id(*chain);
            let proxies = chain_obj
                .map(|c| c.proxies.iter().filter_map(|id| config.proxy_by_id(*id)).collect::<Vec<_>>())
                .unwrap_or_default();
            for (i, p) in proxies.iter().enumerate() {
                println!("  hop {}: {} [{}] {}:{}", i + 1, p.name, p.kind.as_str(), p.host, p.port);
            }
            println!("action: proxified (host {host}:{port} not resolved locally)");
        }
        Decision::Direct { rule, reason } => {
            println!("route: direct ({}{})", reason, rule.map(|r| format!(" rule #{r}")).unwrap_or_default());
        }
        Decision::Block { rule } => {
            let origin = if *rule == 0 { "DNS policy: no chain can carry it".to_string() } else { format!("rule #{rule}") };
            println!("route: BLOCKED ({origin}) — connection refused, neither proxied nor leaked");
        }
    }
    0
}

fn cmd_serve(args: &Args) -> u8 {
    let Some(socks5_addr) = args.socks5.clone() else {
        eprintln!("error: `serve --socks5 <host:port>` is required");
        return 2;
    };
    let config = match load_config(args) {
        Ok(c) => c,
        Err(code) => return code,
    };
    let errors = config.validate();
    if !errors.is_empty() {
        eprintln!("error: config is invalid, refusing to serve:");
        for e in &errors {
            eprintln!("  - {}", e.message);
        }
        return 1;
    }
    let listener = match std::net::TcpListener::bind(&socks5_addr) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("error: cannot bind SOCKS5 server on {socks5_addr}: {e}");
            return 1;
        }
    };
    println!("serving SOCKS5 on {socks5_addr} (config: {})", args.config.display());
    if let Some(app) = &args.app {
        println!("rule matching with --app {app}");
    }
    if let Err(e) = engine::serve(listener, config, args.app.clone()) {
        eprintln!("error: {e}");
        return 1;
    }
    0
}

/// Profiles management from the CLI — parity with the GUI's Profiles dialog
/// (fnd_13: New / Manage / Save As / Load / Import / Export / Delete / Rename).
/// Profiles live in a `profiles/` folder beside the active Settings.ini (or a
/// `--profiles-dir`). Output is plain text so it composes with redirection.
/// One line of the WFP acceptance gate: did it hold, what it means, and what to do
/// if not. Pure so the pass/fail semantics are testable on a machine with no driver
/// (which is every machine until the operator builds one).
#[cfg(windows)]
/// The application a flow row was credited to, from a decision line shaped
/// `拦截 {app} → {host}:{port} …→ {…}` (see `intercept.rs`). Returns None for any other
/// line, so a stray log entry cannot be mistaken for attribution evidence.
pub(crate) fn app_from_flow_line(msg: &str) -> Option<String> {
    let rest = msg.strip_prefix("拦截 ")?;
    // the first " → " ends the application name; anything after it is the destination
    // and the decision (and for UDP, a " (UDP)" marker trails the destination, which is
    // why the suffix must NOT be required here)
    let app = rest.split(" → ").next()?;
    if app.is_empty() || app == rest {
        None
    } else {
        Some(app.to_string())
    }
}

/// Whether a consenting "wfp --verify" run may hand the driver its own token
/// pool. The driver redirects to whichever pool it was given last, so taking the
/// claim from a route that is ALREADY armed would repoint live traffic at listeners
/// that disappear when this diagnostic exits - a self-check must never do that, even
/// briefly. A driver that is off, or ours, or unclaimed is fair game.
pub(crate) fn may_arm_for_self_check(claim_pid: u32, enabled: u32, self_pid: u32) -> bool {
    enabled != 1 || claim_pid == 0 || claim_pid == self_pid
}

pub(crate) fn wfp_verify_report(
    driver: Option<&crate::wfp_ingress::DriverStatus>,
    tokens: usize,
    udp_tokens: usize,
    filters_installed: usize,
    filter_err: Option<u32>,
    redirect_to: Option<&str>,
    flow_app: Option<&str>,
    self_app: &str,
) -> Vec<(bool, &'static str, String)> {
    let mut rows: Vec<(bool, &'static str, String)> = Vec::new();
    match driver {
        None => rows.push((
            false,
            "callout driver present",
            "tpdrv_wfp.sys is not loaded (or it refused/short-answered the status IOCTL - an ABI mismatch looks identical from here): build driver_wfp/ with the WDK, sign it, load it in a VM".into(),
        )),
        Some(st) => {
            {
                // A control device that ANSWERS is not yet a working callout. If
                // FwpsCalloutRegister1 or FwpsRedirectHandleCreate0 failed inside the
                // driver, the filters still install, every flow still reaches the
                // sublayer, and the permit-if-callout-unregistered flag means the
                // traffic goes DIRECT: the app keeps working and nothing is proxied.
                // Name the missing half here instead of leaving the operator to infer
                // it from the redirect row.
                let capable = st.callouts_registered >= 1 && st.redirect_handle_valid == 1;
                let why = if capable {
                    format!(
                        "control device answered (callouts={}, redirect handle={})",
                        st.callouts_registered,
                        st.redirect_handle_valid,
                    )
                } else {
                    format!(
                        "loaded but callouts_registered={} redirect_handle_valid={}: filters pointing at an unregistered callout permit traffic DIRECT, so DriverEntry failed part-way",
                        st.callouts_registered,
                        st.redirect_handle_valid,
                    )
                };
                rows.push((capable, "callout driver present", why));
            }
            rows.push((
                st.enabled == 1 && st.token_count as usize >= tokens && st.udp_token_count as usize >= udp_tokens,
                "driver configured by this service",
                format!(
                    "enabled={} tcp_tokens={} udp_tokens={} claim_pid={}{}",
                    st.enabled,
                    st.token_count,
                    st.udp_token_count,
                    st.proxy_pid,
                    if st.proxy_pid == std::process::id() {
                        String::new()
                    } else {
                        // the driver only takes configuration from whoever claimed it, so
                        // a stale claim from a crashed service looks exactly like a
                        // refusing driver — say which pid holds it and how to clear it
                        format!(" (claim held by pid {}; restart the TpDrvWfp service to clear it)", st.proxy_pid)
                    }
                ),
            ));
            // A driver that leaves datagrams direct is not "working, mostly": the app
            // keeps its real address for those flows. Counted in the driver precisely so
            // this row can fail instead of the silence doing it.
            rows.push((
                st.udp_untrackable == 0,
                "no datagram was left unproxied for want of a flow handle",
                if st.udp_untrackable == 0 {
                    "the callout tracked every UDP flow it saw".to_string()
                } else {
                    format!(
                        "{} UDP flow(s) were permitted untouched because the engine                          indicated no flow handle, so their tokens could never be                          returned — those apps are sending datagrams directly",
                        st.udp_untrackable
                    )
                },
            ));
        }
    }
    rows.push((
        tokens > 0 && udp_tokens > 0,
        "engine token listeners bound",
        format!("{tokens} TCP + {udp_tokens} UDP (needs TPROXIER_WFP_INGRESS=1)"),
    ));
    rows.push(match filter_err {
        Some(code) => (
            false,
            "per-app redirect filters installed",
            format!(
                "FwpmFilterAdd0 failed with {code:#x}{} — filters change real routing, so this needs an elevated shell and the consent flag",
                if code == 5 || code == 0x8007_0005 { " (E_ACCESSDENIED)" } else { "" }
            ),
        ),
        None if filters_installed == 0 => (
            false,
            "per-app redirect filters installed",
            "not attempted: --verify is read-only unless you also pass --i-consent-to-install-wfp-filters".to_string(),
        ),
        None => (
            true,
            "per-app redirect filters installed",
            format!("{filters_installed} filter(s) in the redirect sublayer, withdrawn when this process exits"),
        ),
    });
    rows.push(match redirect_to {
        Some(dst) => (true, "a connect was redirected and its ORIGINAL destination recovered", dst.to_string()),
        None => (
            false,
            "a connect was redirected and its ORIGINAL destination recovered",
            "the probe connect left this machine untouched and came back unredirected — expected while the driver is absent".into(),
        ),
    });
    // Per-process attribution is the ONE thing the WFP route adds over the ws2_32 hook
    // (services, console apps with no message pump, processes started before install),
    // so a green "redirected" row without it would be a half-proof: the name in the
    // flow row came from the record's pid, which only the kernel could have filled in.
    rows.push(match (redirect_to, flow_app) {
        (Some(_), Some(app)) if app == self_app => (
            true,
            "the kernel credited the flow to this process",
            format!("redirect-context pid resolved to {app}"),
        ),
        (Some(_), Some(app)) => (
            false,
            "the kernel credited the flow to this process",
            format!("the redirected flow was attributed to {app}, not {self_app} — check what the classify callback stores in the record's pid"),
        ),
        (Some(_), None) => (
            false,
            "the kernel credited the flow to this process",
            format!("tunnel established but no 拦截 line named an application (image_basename({self_app}) failed or the record pid was zero)"),
        ),
        // nothing arrived, so attribution is unevaluable — say that rather than
        // implying the pid plumbing is broken
        (None, _) => (
            false,
            "the kernel credited the flow to this process",
            "not evaluated: no redirected flow arrived".into(),
        ),
    });
    rows
}

/// What `wfp` would do, decided WITHOUT touching the BFE. Split out because the
/// interesting properties (never install without consent; never install filters
/// whose callout is absent; never install filters with nothing to apply them to)
/// must hold on machines that cannot reach WFP at all — including this one.
#[cfg(windows)]
fn wfp_plan(
    apps: &[String],
    apply: bool,
    consent: bool,
    driver_present: bool,
    token_count: usize,
) -> Result<(Vec<String>, bool), String> {
    use crate::wfp::Wfp;
    let list: Vec<&str> = apps.iter().map(|a| a.trim()).filter(|a| !a.is_empty()).collect();
    let mut lines = Vec::new();
    if driver_present {
        lines.push("callout driver: present (\\Device\\TpDrvWfp)".to_string());
    } else {
        lines.push("callout driver: NOT LOADED — nothing can redirect yet".to_string());
        lines.push("    build driver_wfp/ with the WDK, sign it, load it in a VM".to_string());
    }
    lines.push(format!("engine ingress AT ENTRY: {token_count} token port(s) bound (a --verify run binds its own listeners before the gate prints)"));
    // An empty whitelist is fatal only when this run would actually install filters:
    // wfp --verify is the diagnostic that tells you WHY nothing works, and refusing to
    // print the read-only rows (is the .sys even loaded?) because a profile has no apps
    // is the tool hiding the answer it exists to give.
    if list.is_empty() && apply {
        return Err("the app whitelist is empty: the WFP route redirects per program, so turn on 程序白名单 and list at least one executable".to_string());
    }
    if list.is_empty() {
        lines.push("  (app whitelist empty: the per-program rows below stay unevaluated - turn on 程序白名单 and list an executable, then pass --i-consent-to-install-wfp-filters to test the redirect itself)".to_string());
    }
    if apply && !consent {
        return Err(
            "refusing to install WFP filters: pass --i-consent-to-install-wfp-filters \
             (they change real routing for the listed programs)"
                .to_string(),
        );
    }
    for a in &list {
        // four per program: v4/v6 × tcp/udp, matching what wfp_route::commit installs
        for (v6, proto) in [
            (false, crate::wfp::IPPROTO_TCP),
            (false, crate::wfp::IPPROTO_UDP),
            (true, crate::wfp::IPPROTO_TCP),
            (true, crate::wfp::IPPROTO_UDP),
        ] {
            lines.push(format!("  {}", Wfp::preview_route(a, v6, proto)));
        }
    }
    if apply && !driver_present {
        // Filters naming an unregistered callout are inert at best. Install nothing
        // rather than leaving the operator believing the route is live.
        return Err("the callout driver is not loaded, so these filters would do nothing".to_string());
    }
    Ok((lines, apply))
}

fn cmd_wfp(args: &Args) -> u8 {
    let config = match load_config(args) {
        Ok(c) => c,
        Err(e) => return e,
    };
    #[cfg(not(windows))]
    {
        let _ = (&config, args);
        eprintln!("error: the WFP route is Windows-only");
        return 1;
    }
    #[cfg(windows)]
    {
        use crate::{intercept, monitor::Monitor, wfp, wfp_ingress};
        use std::sync::{Arc, RwLock};

        let driver = wfp_ingress::driver_present();
        let tokens = if driver { wfp_ingress::token_ports().len() } else { 0 };
        let (lines, install) =
            match wfp_plan(&config.settings.app_whitelist, args.apply, args.consent_wfp, driver, tokens) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("error: {e}");
                    return 2;
                }
            };
        for l in &lines {
            println!("{l}");
        }
        if args.verify {
            // The acceptance gate for the WFP route. Read-only wherever it can be:
            // it asks the driver for status instead of configuring it, and its probe
            // connect goes to TEST-NET-3, which is unroutable by design — so the only
            // way it can SUCCEED is if a callout actually redirected the flow and the
            // original destination came back through the redirect context.
            let probe = "198.51.100.99:80";
            let dstat = wfp_ingress::status().ok();
            let cfg = {
                unsafe { std::env::set_var("TPROXIER_WFP_INGRESS", "1") };
                let c = Arc::new(RwLock::new(config.clone()));
                let m = Arc::new(Monitor::new());
                match intercept::spawn_servers(c, m.clone()) {
                    Ok(s) => Some((s, m)),
                    Err(e) => {
                        eprintln!("error: could not start the engine listeners: {e}");
                        return 1;
                    }
                }
            };
            let (_servers, mon) = cfg.expect("checked above");
            let tokens = wfp_ingress::token_ports().len();
            let udp_tokens = wfp_ingress::udp_token_ports().len();
            // install a filter for THIS executable only: the smallest possible blast
            // radius for a test that touches real routing
            let exe = std::env::current_exe().ok().map(|p| p.to_string_lossy().to_string());
            let mut installed = 0usize;
            let mut ferr: Option<u32> = None;
            // Installing filters changes real routing, so --verify honours the SAME
            // consent gate as --apply: without it we report everything else read-only
            // and say why the decisive row cannot be evaluated.
            let consented = args.consent_wfp;
            let exe = exe.filter(|_| consented);
            if consented {
                // Redirect targets are the token ports the driver was GIVEN, and the
                // claim is one-process-wide. Taking it from a route that is already
                // armed would repoint live traffic at listeners that vanish when this
                // diagnostic exits, so the gate only arms itself when nothing else
                // owns the driver (or when it is us).
                match wfp_ingress::status() {
                    Ok(st) if !may_arm_for_self_check(st.proxy_pid, st.enabled, std::process::id()) => {
                        println!(
                            "  note: the driver is armed by pid {} - this run leaves a live route alone, so the rows below describe that route, not this one",
                            st.proxy_pid,
                        );
                    }
                    _ => {
                        if let Err(e) = wfp_ingress::configure_driver(true) {
                            println!("  note: this run could not arm the driver: {e}");
                        }
                    }
                }
            }
            // Hoisted so the session outlives the probe connect below: a dynamic WFP
            // session withdraws its filters the instant it closes, so a session dropped
            // at the end of the install block leaves the probe unredirected - which is
            // how this gate stayed unpassable even with a correct callout installed.
            let mut open_session: Option<wfp::Wfp> = None;
            if let Some(path) = &exe {
                open_session = wfp::Wfp::open().ok();
                if open_session.is_none() {
                    ferr = Some(0xE000_0001); // FwpmEngineOpen0 refused
                }
                if let Some(session) = &mut open_session {
                    let app = wfp::AppId::new(path);
                    for v6 in [false, true] {
                        // same per-transport split as the real deployment, so what
                    // `netsh wfp show state` shows here matches --apply
                    match session.route_app_to_callout(&app, v6, wfp::IPPROTO_TCP)
                        .and_then(|id| session.route_app_to_callout(&app, v6, wfp::IPPROTO_UDP).map(|_| id))
                    {
                            Ok(_) => installed += 1,
                            Err(code) => ferr = Some(code),
                        }
                    }
                }
            }
            let mut redirect_to: Option<String> = None;
            let mut flow_app: Option<String> = None;
            if installed > 0 {
                if let Ok(stream) = std::net::TcpStream::connect(probe) {
                    drop(stream);
                    let (lines, _) = mon.since(0);
                    if lines.iter().any(|l| l.message.contains(probe) && l.message.contains("隧道已建立")) {
                        redirect_to = Some(probe.to_string());
                    }
                    // the DECISION line is what names the application, and that name can
                    // only have come from the record's pid → per-process attribution
                    flow_app = lines
                        .iter()
                        .filter(|l| l.message.contains(probe))
                        .find_map(|l| app_from_flow_line(&l.message));
                }
            }
            drop(open_session);

            let self_app = std::env::current_exe()
                .ok()
                .and_then(|p| p.file_name().map(|s| s.to_string_lossy().to_string()))
                .unwrap_or_default();
            let rows = wfp_verify_report(
                dstat.as_ref(),
                tokens,
                udp_tokens,
                installed,
                ferr,
                redirect_to.as_deref(),
                flow_app.as_deref(),
                &self_app,
            );
            println!("WFP route acceptance gate:");
            let mut ok = true;
            for (passed, what, detail) in &rows {
                println!("  {} {what} — {detail}", if *passed { "PASS" } else { "FAIL" });
                ok &= *passed;
            }
            println!(
                "\n{}",
                if ok {
                    "WFP redirect verified end to end."
                } else {
                    "Not yet working. Everything except the loaded .sys is in place here; see docs/WFP_ROADMAP.md."
                }
            );
            return if ok { 0 } else { 1 };
        }

        if !install {
            println!("\ndry run: nothing was installed. Add --apply --i-consent-to-install-wfp-filters.");
            println!("note: the token ports above exist only while the engine runs, so --apply");
            println!("starts its own engine listeners in this process.");
            return 0;
        }

        // ONE implementation of the arming sequence, shared with the GUI. prepare()
        // latches the ingress path (so the listeners created next actually bind token
        // ports) and enforces the refusal rules; commit() installs the filters and hands
        // the driver this process's pool. Duplicating that here is how the CLI once ended
        // up installing TCP-only filters while the driver reserved UDP tokens.
        let cfg = Arc::new(RwLock::new(config.clone()));
        let mon = Arc::new(Monitor::new());
        if let Err(e) = crate::wfp_route::prepare(&config, args.consent_wfp) {
            eprintln!("error: {e}");
            return 1;
        }
        if let Err(e) = intercept::spawn_servers(cfg.clone(), mon.clone()) {
            eprintln!("error: could not start the engine listeners: {e}");
            return 1;
        }
        let route = match crate::wfp_route::commit(&config, &mon) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("error: {e}");
                return 1;
            }
        };
        let installed = route.installed();
        let st = match wfp_ingress::status() {
            Ok(st) => st,
            Err(e) => {
                eprintln!("error: filters are installed but the driver cannot be read: {e}");
                return 1;
            }
        };
        println!(
            "driver configured: enabled={} proxy_pid={} tokens={} udp={} callouts={} handle={}",
            st.enabled,
            st.proxy_pid,
            st.token_count,
            st.udp_token_count,
            st.callouts_registered,
            st.redirect_handle_valid
        );
        let apps = config.settings.app_whitelist.iter().map(|a| a.trim()).filter(|a| !a.is_empty()).count();
        println!("  {installed} redirect filter(s) covering {apps} whitelisted program(s), v4 + v6");
        if args.once {
            // Our listeners die with us, so an armed driver would redirect the next
            // whitelisted connect to a closed port. Route::drop disarms it and withdraws
            // the filters (same code path the GUI's stop button takes).
            drop(route);
            println!("--once: driver disarmed, {installed} filter(s) withdrawn with the session");
            return 0;
        }
        println!(
            "{installed} filter(s) live in sublayer {}; Ctrl+C (or any exit) removes them with it.",
            wfp::fmt_guid(&wfp::REDIRECT_SUBLAYER)
        );
        println!("verify with:  netsh wfp show state file=wfp-state.xml");
        console_stop::install();
        let mut seen = st;
        loop {
            if console_stop::requested() {
                drop(route);
                println!("driver disarmed (enabled=0) and {installed} filter(s) withdrawn");
                return 0;
            }
            // A callout driver that is stopped and started again comes back INERT, and
            // traffic then flows exactly as it would with the route switched off — no
            // error anywhere. Poll, and re-push if the driver's view drifted from ours.
            match wfp_ingress::ensure_armed() {
                Ok(now) => {
                    if now != seen {
                        println!(
                            "driver: enabled={} pid={} tcp_tokens={} udp_tokens={}                              udp_flows={} callouts={} handle={}",
                            now.enabled,
                            now.proxy_pid,
                            now.token_count,
                            now.udp_token_count,
                            now.udp_active_flows,
                            now.callouts_registered,
                            now.redirect_handle_valid
                        );
                        seen = now;
                    }
                }
                Err(e) => eprintln!("warning: driver status unavailable: {e}"),
            }
            std::thread::sleep(Duration::from_secs(2));
        }
    }
}


/// Ctrl+C must not leave the kernel redirect armed and pointing at token ports that die
/// with this process. The handler therefore only flags; the supervision loop notices,
/// disarms the driver, and exits. Issuing the IOCTL from inside the handler is not an
/// option — it runs on a system thread while the process is already being torn down.
#[cfg(windows)]
mod console_stop {
    use std::sync::atomic::{AtomicBool, Ordering};

    static STOP: AtomicBool = AtomicBool::new(false);

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn SetConsoleCtrlHandler(handler: Option<unsafe extern "system" fn(u32) -> i32>, add: i32) -> i32;
    }

    unsafe extern "system" fn on_ctrl(_ctrl_type: u32) -> i32 {
        STOP.store(true, Ordering::SeqCst);
        // TRUE = handled here, so the default handler cannot kill us mid-disarm; the
        // loop returns on its own within one poll interval.
        1
    }

    pub fn install() {
        unsafe {
            SetConsoleCtrlHandler(Some(on_ctrl), 1);
        }
    }

    pub fn requested() -> bool {
        STOP.load(Ordering::SeqCst)
    }
}

#[cfg(not(windows))]
mod console_stop {
    pub fn install() {}
    pub fn requested() -> bool {
        false
    }
}

fn cmd_profiles(args: &Args) -> u8 {
    let dir = profiles_dir(args);
    let store = match ProfileStore::new(&dir) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: cannot open profiles dir {}: {e}", dir.display());
            return 1;
        }
    };
    let p = &args.positional;
    let sub = p.first().map(|s| s.as_str()).unwrap_or("list");
    macro_rules! arg_at {
        ($i:expr) => {
            match p.get($i) {
                Some(v) => v.as_str(),
                None => {
                    eprintln!("error: profiles {sub} needs an argument");
                    return 2;
                }
            }
        };
    }
    match sub {
        "list" => {
            for n in store.list() {
                println!("{n}");
            }
            0
        }
        "new" => {
            let name = arg_at!(1);
            match store.save(name, &Config::default()) {
                Ok(()) => {
                    println!("created profile \"{name}\" in {}", dir.display());
                    0
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    1
                }
            }
        }
        "save" => {
            // Snapshot the CURRENT --config into the store under NAME.
            let name = arg_at!(1);
            match Config::load(&args.config) {
                Ok(cfg) => match store.save(name, &cfg) {
                    Ok(()) => {
                        println!("saved current config as \"{name}\"");
                        0
                    }
                    Err(e) => {
                        eprintln!("error: {e}");
                        1
                    }
                },
                Err(e) => {
                    eprintln!("error: {e}");
                    1
                }
            }
        }
        "load" => {
            // Emit the named profile's ini to stdout (redirect into Settings.ini).
            let name = arg_at!(1);
            match store.load(name) {
                Ok(cfg) => {
                    print!("{}", cfg.serialize());
                    0
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    1
                }
            }
        }
        "delete" => {
            let name = arg_at!(1);
            match store.delete(name) {
                Ok(()) => {
                    println!("deleted \"{name}\"");
                    0
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    1
                }
            }
        }
        "rename" => {
            let a = arg_at!(1);
            let b = arg_at!(2);
            match store.rename(a, b) {
                Ok(()) => {
                    println!("renamed \"{a}\" -> \"{b}\"");
                    0
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    1
                }
            }
        }
        "import" => {
            let src = arg_at!(1);
            let name = arg_at!(2);
            match store.import(Path::new(src), name) {
                Ok(()) => {
                    println!("imported {src} as \"{name}\"");
                    0
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    1
                }
            }
        }
        "export" => {
            let name = arg_at!(1);
            let dest = arg_at!(2);
            match store.export(name, Path::new(dest)) {
                Ok(()) => {
                    println!("exported \"{name}\" -> {dest}");
                    0
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    1
                }
            }
        }
        other => {
            eprintln!("error: unknown profiles subcommand \"{other}\" (list/new/save/load/delete/rename/import/export)");
            2
        }
    }
}

/// Where profiles live: `--profiles-dir` is not a flag here, so mirror the GUI —
/// a `profiles/` folder beside the active config file.
fn profiles_dir(args: &Args) -> PathBuf {
    args.config.parent().unwrap_or(Path::new(".")).join("profiles")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arg(cmd: &str, rest: &[&str]) -> Vec<String> {
        let mut v = vec!["trans-proxier".to_string(), cmd.to_string()];
        v.extend(rest.iter().map(|s| s.to_string()));
        v
    }

    #[test]
    fn parses_profiles_subcommand_and_positionals() {
        let a = parse_args(arg("profiles", &["save", "work"])).unwrap();
        assert_eq!(a.cmd, "profiles");
        assert_eq!(a.positional, vec!["save".to_string(), "work".to_string()]);
    }

    #[test]
    fn profiles_list_new_load_roundtrip_via_tempdir() {
        let dir = std::env::temp_dir().join(format!("tpcli-prof-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("Settings.ini");
        // a real config to snapshot
        Config::default().write(&config_path).unwrap();

        let mut a = parse_args(arg("profiles", &["save", "snap1"])).unwrap();
        a.config = config_path.clone();
        assert_eq!(cmd_profiles(&a), 0, "save current config as snap1");

        let mut l = parse_args(arg("profiles", &["list"])).unwrap();
        l.config = config_path.clone();
        assert_eq!(cmd_profiles(&l), 0);

        let mut d = parse_args(arg("profiles", &["delete", "snap1"])).unwrap();
        d.config = config_path.clone();
        assert_eq!(cmd_profiles(&d), 0);

        // deleting a missing profile errors (non-zero), not panics
        let mut d2 = parse_args(arg("profiles", &["delete", "nope"])).unwrap();
        d2.config = config_path.clone();
        assert_ne!(cmd_profiles(&d2), 0);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn profiles_unknown_subcommand_is_error() {
        let dir = std::env::temp_dir().join(format!("tpcli-prof-bad-{}", std::process::id()));
        let mut a = parse_args(arg("profiles", &["frobnicate"])).unwrap();
        a.config = dir.join("Settings.ini");
        assert_eq!(cmd_profiles(&a), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn route_accepts_flags_or_positional() {
        let dir = std::env::temp_dir().join(format!("tpcli-route-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = dir.join("Settings.ini");
        Config::default().write(&cfg).unwrap(); // 127.0.0.1 is in the default exclusion list -> direct

        // --host/--port flags must work, not only positional (regression guard).
        let mut by_flag = parse_args(arg("route", &["--host", "127.0.0.1", "--port", "80"])).unwrap();
        by_flag.config = cfg.clone();
        assert_eq!(cmd_route(&by_flag), 0, "route via flags should succeed");

        let mut by_pos = parse_args(arg("route", &["127.0.0.1", "80"])).unwrap();
        by_pos.config = cfg.clone();
        assert_eq!(cmd_route(&by_pos), 0, "route via positional should work");

        // host without a port is a clear usage error, not a panic.
        let mut bad = parse_args(arg("route", &["--host", "example.com"])).unwrap();
        bad.config = cfg.clone();
        assert_eq!(cmd_route(&bad), 2);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn route_parses_proto_flag() {
        let a = parse_args(arg("route", &["example.com", "443", "--proto", "udp"])).unwrap();
        assert_eq!(a.proto.as_deref(), Some("udp"));
        let b = parse_args(arg("route", &["example.com", "443"])).unwrap();
        assert_eq!(b.proto, None, "absent --proto means any");
    }

    #[test]
    fn route_validates_proto() {
        let dir = std::env::temp_dir().join(format!("tpcli-route-proto-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = dir.join("Settings.ini");
        Config::default().write(&cfg).unwrap();
        for p in ["tcp", "udp", "any"] {
            let mut a = parse_args(arg("route", &["--host", "127.0.0.1", "--port", "443", "--proto", p])).unwrap();
            a.config = cfg.clone();
            assert_eq!(cmd_route(&a), 0, "valid --proto {p} must run");
        }
        let mut bad = parse_args(arg("route", &["--host", "127.0.0.1", "--port", "443", "--proto", "carrier-pigeon"])).unwrap();
        bad.config = cfg.clone();
        assert_eq!(cmd_route(&bad), 2, "unknown --proto must be a usage error");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(all(test, windows))]
mod wfp_verb_tests {
    use super::{app_from_flow_line, may_arm_for_self_check, wfp_plan, wfp_verify_report};

    fn apps(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    /// The decisive row must not be satisfied by "a tunnel happened": the whole point of
    /// the kernel route is that the flow is credited to the process that opened it.
    /// UDP that the callout could not track is sent direct — no leak, but also no
    /// proxy, and nothing on the wire would reveal it. The counter exists so this row
    /// can fail instead of the silence doing it.
    #[test]
    fn untrackable_datagrams_fail_the_gate_rather_than_passing_quietly() {
        let st = crate::wfp_ingress::DriverStatus {
            enabled: 1,
            callouts_registered: 1,
            redirect_handle_valid: 1,
            proxy_pid: 1,
            token_count: 16,
            udp_token_count: 16,
            udp_untrackable: 3,
            ..Default::default()
        };
        let rows = wfp_verify_report(
            Some(&st), 16, 16, 2, None, Some("198.51.100.99:80"), Some("self.exe"), "self.exe");
        let row = rows.iter().find(|r| r.1.contains("unproxied")).expect("row present");
        assert!(!row.0, "three untracked datagram flows must not read as a pass");
        assert!(row.2.contains("3"), "and the count belongs in the explanation: {}", row.2);

        let st0 = crate::wfp_ingress::DriverStatus { udp_untrackable: 0, ..st };
        let rows = wfp_verify_report(
            Some(&st0), 16, 16, 2, None, Some("198.51.100.99:80"), Some("self.exe"), "self.exe");
        let row = rows.iter().find(|r| r.1.contains("unproxied")).expect("row present");
        assert!(row.0, "a driver that tracked everything passes: {}", row.2);
    }

    #[test]
    fn a_loaded_driver_that_registered_nothing_must_not_pass_the_gate() {
        // The silent-direct failure: the .sys loads, its control device answers the
        // status IOCTL, the filters install happily, and because they carry
        // permit-if-callout-unregistered, ALL TRAFFIC GOES DIRECT while the app keeps
        // working normally. Only the gate can see this, so the gate must fail on it.
        let base = crate::wfp_ingress::DriverStatus {
            enabled: 1,
            token_count: 16,
            udp_token_count: 16,
            redirect_handle_valid: 1,
            ..Default::default()
        };
        let row_of = |st: &crate::wfp_ingress::DriverStatus| {
            let rows = wfp_verify_report(Some(st), 16, 16, 2, None, None, None, "self.exe");
            rows.into_iter().find(|r| r.1 == "callout driver present").expect("row present")
        };

        let no_callout = row_of(&base);
        assert!(!no_callout.0, "callouts_registered=0 must FAIL the gate: {}", no_callout.2);
        assert!(no_callout.2.contains("unregistered"), "the detail must name the cause: {}", no_callout.2);

        let no_handle = row_of(&crate::wfp_ingress::DriverStatus { callouts_registered: 1, redirect_handle_valid: 0, ..base });
        assert!(!no_handle.0, "a missing redirect handle must FAIL the gate: {}", no_handle.2);

        // and the inverse, so the row cannot pass merely by always failing
        let both = row_of(&crate::wfp_ingress::DriverStatus { callouts_registered: 1, redirect_handle_valid: 1, ..base });
        assert!(both.0, "a fully registered driver must pass: {}", both.2);
    }
    #[test]

    fn attribution_must_name_this_process_and_not_someone_else() {
        let st = crate::wfp_ingress::DriverStatus {
            enabled: 1,
            callouts_registered: 1,
            redirect_handle_valid: 1,
            proxy_pid: 1,
            token_count: 16,
            udp_token_count: 16,
            ..Default::default()
        };
        let attr_of = |rows: Vec<(bool, &'static str, String)>| {
            rows.into_iter().find(|r| r.1.contains("credited the flow")).expect("row present")
        };

        let other = wfp_verify_report(
            Some(&st), 16, 16, 2, None, Some("198.51.100.99:80"), Some("other.exe"), "self.exe");
        let row = attr_of(other);
        assert!(!row.0, "a flow credited to another image must FAIL the gate: {}", row.2);

        let mine = wfp_verify_report(
            Some(&st), 16, 16, 2, None, Some("198.51.100.99:80"), Some("self.exe"), "self.exe");
        let row = attr_of(mine);
        assert!(row.0, "the matching case must pass: {}", row.2);

        // no flow at all ⇒ unevaluable, stated as such — never a silent pass
        let none = wfp_verify_report(Some(&st), 16, 16, 2, None, None, None, "self.exe");
        let row = attr_of(none);
        assert!(!row.0 && row.2.contains("not evaluated"), "{}", row.2);
    }

    #[test]
    fn the_app_name_is_read_from_the_decision_line_only() {
        assert_eq!(
            app_from_flow_line("拦截 firefox.exe → 198.51.100.99:80 (UDP)→ 代理").as_deref(),
            Some("firefox.exe"),
            "UDP lines carry a marker after the destination and must still parse"
        );
        assert_eq!(
            app_from_flow_line("拦截 self.exe → 198.51.100.99:80 → 代理").as_deref(),
            Some("self.exe")
        );
        assert_eq!(app_from_flow_line("中继: 隧道已建立 → 198.51.100.99:80 via socks5"), None,
            "a tunnel line names no application");
        assert_eq!(app_from_flow_line("拦截  → x:80 → 代理"), None, "an empty app is not attribution");
    }

    #[test]
    fn the_gate_reports_the_driver_being_absent_without_blaming_the_rest() {
        use crate::wfp_ingress::DriverStatus;
        let rows = wfp_verify_report(None, 16, 16, 2, None, None, None, "self.exe");
        let failed: Vec<_> = rows.iter().filter(|r| !r.0).map(|r| r.1).collect();
        assert!(failed.iter().any(|f| f.contains("callout driver present")), "{failed:?}");
        assert!(failed.iter().any(|f| f.contains("redirected")), "the decisive check must fail too: {failed:?}");
        // the parts we control are green even with no driver
        assert!(rows.iter().any(|r| r.1.contains("token listeners") && r.0));
        assert!(rows.iter().any(|r| r.1.contains("filters installed") && r.0));
        let _ = std::any::type_name::<DriverStatus>();
    }

    #[test]
    fn the_gate_names_access_denied_as_the_elevation_it_needs() {
        let rows = wfp_verify_report(Some(&crate::wfp_ingress::DriverStatus::default()), 16, 16, 0, Some(5), None, None, "self.exe");
        let f = rows.iter().find(|r| r.1.contains("filters installed")).unwrap();
        assert!(!f.0);
        assert!(f.2.contains("E_ACCESSDENIED") && f.2.contains("elevated"), "{}", f.2);
    }

    #[test]
    fn the_gate_only_passes_when_the_destination_came_back() {
        let st = crate::wfp_ingress::DriverStatus {
            enabled: 1,
            callouts_registered: 1,
            redirect_handle_valid: 1,
            token_count: 16,
            udp_token_count: 16,
            ..Default::default()
        };
        let rows = wfp_verify_report(Some(&st), 16, 16, 2, None, Some("198.51.100.99:80"), Some("trans-proxier.exe"), "trans-proxier.exe");
        assert!(rows.iter().all(|r| r.0), "{:?}", rows.iter().filter(|r| !r.0).map(|r| (r.1, &r.2)).collect::<Vec<_>>());
    }

    #[test]
    fn dry_run_needs_no_consent_and_says_the_driver_is_absent() {
        let (lines, install) = wfp_plan(&apps(&[r"C:\Games\game.exe"]), false, false, false, 0).unwrap();
        assert!(!install);
        let text = lines.join("\n");
        assert!(text.contains("NOT LOADED"), "{text}");
        assert!(text.contains("ALE_CONNECT_REDIRECT_V4"), "{text}");
        assert!(text.contains(r"C:\GAMES\GAME.EXE"), "preview upper-cases the app id: {text}");
        assert!(text.contains("ALE_CONNECT_REDIRECT_V6"), "both families are previewed");
    }

    #[test]
    fn a_read_only_verify_still_reports_with_an_empty_whitelist() {
        // The VM's very first run looks like this: no apps listed yet. It must still
        // answer the question that matters there - is the callout loaded? - instead of
        // exiting 2 before printing anything.
        let (lines, install) = wfp_plan(&[], false, false, false, 0)
            .expect("a read-only verify must never refuse to report");
        assert!(!install, "nothing may be installed");
        let text = lines.join("\n");
        assert!(text.contains("NOT LOADED"), "{text}");
        assert!(text.contains("whitelist empty"), "the empty scope is stated, not hidden: {text}");

        // but the same emptiness IS fatal once filters would really be installed
        let e = wfp_plan(&[], true, true, true, 16).unwrap_err(); // apply with no scope
        assert!(e.contains("whitelist is empty"), "{e}");
    }
    #[test]
    fn a_self_check_never_steals_the_claim_from_a_live_route() {
        assert!(may_arm_for_self_check(0, 0, 100), "nothing claimed it: free to arm");
        assert!(may_arm_for_self_check(100, 1, 100), "already ours: re-arming is ours");
        assert!(may_arm_for_self_check(7, 0, 100), "driver off: nothing live to disturb");
        // the one that matters: another process is carrying traffic right now
        assert!(!may_arm_for_self_check(7, 1, 100), "claim theft would repoint live flows at a dying listener");
    }
    #[test]
    fn apply_requires_explicit_consent() {
        let e = wfp_plan(&apps(&["a.exe"]), true, false, true, 16).unwrap_err();
        assert!(e.contains("--i-consent-to-install-wfp-filters"), "{e}");
    }

    #[test]
    fn apply_refuses_when_the_callout_driver_is_missing() {
        // Installing filters whose callout is unregistered would leave the operator
        // believing traffic is redirected when nothing happens.
        let e = wfp_plan(&apps(&["a.exe"]), true, true, false, 0).unwrap_err();
        assert!(e.contains("would do nothing"), "{e}");
    }

    #[test]
    fn empty_whitelist_is_rejected_before_anything_else() {
        let e = wfp_plan(&apps(&["", "   "]), true, true, true, 16).unwrap_err();
        assert!(e.contains("whitelist is empty"), "{e}");
    }

    #[test]
    fn apply_proceeds_when_everything_the_route_needs_is_present() {
        let (lines, install) = wfp_plan(&apps(&["a.exe"]), true, true, true, 16).unwrap();
        assert!(install);
        assert!(lines.iter().any(|l| l.contains("present")));
        assert!(lines.iter().any(|l| l.contains("16 token port(s) bound")));
    }
}
