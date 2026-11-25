//! The long-lived half of the WFP redirect route.
//!
//! `trans-proxier wfp --apply` was, until now, the only way to arm the callout — but it
//! is a one-shot process: its token listeners and its filters (which live in a **dynamic**
//! BFE session) die when it exits. The program the operator actually runs is the GUI /
//! tpinject engine, so arming had to move into something that shares that process's
//! lifetime. That is this module: `prepare` before the engine's listeners exist, `commit`
//! after they do, and a [`Route`] guard whose `Drop` takes the whole route down.
//!
//! Why two phases and not one: the engine binds the token ports inside
//! [`crate::intercept::spawn_servers`], and it only does so when
//! [`crate::wfp_ingress::enabled`] answers true. So the decision must be latched BEFORE
//! the listeners are created, and the driver cannot be handed a token pool until AFTER
//! they exist — handing it an empty pool would redirect flows to ports nobody listens on.
//!
//! The interesting logic is the refusal rules, and they are deliberately separated from
//! the FFI so they can be tested where WFP cannot be reached at all (including this
//! machine): never arm without consent, never without the driver, never without an app
//! whitelist to scope it to, and never before the token ports are bound.

use crate::config::Config;
use crate::monitor::Monitor;

/// A live route: it holds the BFE session, so dropping it withdraws exactly our filters
/// and leaves everyone else's policy alone.
pub struct Route {
    installed: usize,
    /// The dynamic session that owns the filters. Kept alive (and never used directly)
    /// purely so that `Drop` order is: disarm driver → withdraw session.
    #[cfg(windows)]
    _session: crate::wfp::Wfp,
}

impl Route {
    /// How many per-app redirect filters are installed (both address families counted).
    pub fn installed(&self) -> usize {
        self.installed
    }
}

impl Drop for Route {
    fn drop(&mut self) {
        // Order matters: tell the driver to stop redirecting FIRST, because the token
        // ports vanish the moment this process continues its shutdown. Redirecting to a
        // closed port is a refused connection for the whitelisted app — visible, but
        // avoidable, and avoidable exactly here.
        #[cfg(windows)]
        {
            let _ = crate::wfp_ingress::configure_driver(false);
        }
    }
}

/// The decision, with no side effects — so it holds on a machine that cannot reach the
/// BFE at all. Returns the number of filters `commit` would install: one per program,
/// address family and transport.
pub fn plan(
    consent: bool,
    driver_present: bool,
    whitelist_len: usize,
    tokens_bound: usize,
    udp_tokens_bound: usize,
    phase: Phase,
) -> Result<usize, String> {
    if !consent {
        return Err(
            "the WFP route redirects a program's traffic at the kernel, so it needs the same \
             explicit consent as the global hook (同意 WFP 重定向)".to_string(),
        );
    }
    if whitelist_len == 0 {
        return Err(
            "the app whitelist is empty: this route redirects per program, so turn on \
             程序白名单 and list at least one executable — an unscoped filter set would \
             capture the whole machine, including this one"
                .to_string(),
        );
    }
    match phase {
        Phase::Prepare => {
            if !driver_present {
                return Err(
                    "tpdrv_wfp.sys is not loaded: build driver_wfp/ with the WDK, sign it and \
                     load it in a VM (install.ps1 -IDeclareIAmInAVM)"
                        .to_string(),
                );
            }
        }
        Phase::Commit => {
            if tokens_bound == 0 || udp_tokens_bound == 0 {
                let which = if tokens_bound == 0 { "TCP" } else { "UDP" };
                return Err(format!(
                    "no {which} token listeners are bound: the engine must be started with \
                     the route prepared first (prepare() → Engine::start → commit())"
                ));
            }
        }
    }
    Ok(whitelist_len * 4) // v4 + v6, and one filter per transport
}

/// Which of the two calls is asking, because they check different things.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Prepare,
    Commit,
}

/// Phase 1. Validates, then latches the ingress path on so that the engine binds the TCP
/// and UDP token ports when it starts.
pub fn prepare(config: &Config, consent: bool) -> Result<(), String> {
    let apps = scoped_apps(&config);
    plan(
        consent,
        crate::wfp_ingress::driver_present(),
        apps.len(),
        0,
        0,
        Phase::Prepare,
    )?;
    crate::wfp_ingress::enable_at_runtime();
    Ok(())
}

/// Phase 2, after the listeners exist: install one filter pair per whitelisted program,
/// then hand the driver this process's pid and token pools.
#[cfg(windows)]
pub fn commit(config: &Config, monitor: &Monitor) -> Result<Route, String> {
    use crate::wfp::{AppId, Wfp};

    let apps = scoped_apps(config);
    let tokens = crate::wfp_ingress::token_ports();
    let udp = crate::wfp_ingress::udp_token_ports();
    plan(true, true, apps.len(), tokens.len(), udp.len(), Phase::Commit)?;

    let mut session = Wfp::open().map_err(|code| {
        format!(
            "FwpmEngineOpen0 failed with {code:#x} — installing filters needs an elevated \
             process (the route stays off; nothing else was changed)"
        )
    })?;

    let mut installed = 0usize;
    let mut first_err: Option<u32> = None;
    for app in &apps {
        let id = AppId::new(app);
        for v6 in [false, true] {
          for proto in [crate::wfp::IPPROTO_TCP, crate::wfp::IPPROTO_UDP] {
            match session.route_app_to_callout(&id, v6, proto) {
                Ok(_) => installed += 1,
                Err(code) => {
                    if first_err.is_none() {
                        first_err = Some(code);
                    }
                }
            }
          }
        }
    }
    // Partial installation is worse than none: some programs would be proxied by a
    // kernel route the operator believes is off. Withdraw everything and report.
    if installed == 0 {
        return Err(match first_err {
            Some(code) => format!("every redirect filter was refused by the BFE ({code:#x})"),
            None => "no redirect filter was installed".to_string(),
        });
    }
    if let Some(code) = first_err {
        monitor.log(
            "warn",
            format!(
                "WFP 入口: {installed}/{} 个过滤器安装成功，其余被 BFE 拒绝 ({code:#x})",
                apps.len() * 2
            ),
        );
    }

    let st = crate::wfp_ingress::configure_driver(true)
        .map_err(|e| format!("the driver refused our token pool: {e}"))?;
    monitor.log(
        "info",
        format!(
            "WFP 内核重定向已启用: {} 个过滤器, 令牌 {} TCP + {} UDP, 驱动 enabled={} callouts={}",
            installed, st.token_count, st.udp_token_count, st.enabled, st.callouts_registered
        ),
    );
    Ok(Route {
        installed,
        _session: session,
    })
}

#[cfg(not(windows))]
pub fn commit(_config: &Config, _monitor: &Monitor) -> Result<Route, String> {
    Err("the WFP route is Windows-only".to_string())
}

/// The programs the route would capture — the same trimming/emptiness rules the CLI's
/// `wfp` verb uses, so preview and reality cannot disagree.
pub fn scoped_apps(config: &Config) -> Vec<String> {
    config
        .settings
        .app_whitelist
        .iter()
        .map(|a| a.trim().to_string())
        .filter(|a| !a.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consent_is_required_before_anything_else() {
        // driver present, whitelist populated: consent still wins
        let e = plan(false, true, 1, 0, 0, Phase::Prepare).unwrap_err();
        assert!(e.contains("consent"), "{e}");
    }

    #[test]
    fn an_empty_whitelist_is_refused_rather_than_capturing_the_machine() {
        for phase in [Phase::Prepare, Phase::Commit] {
            let e = plan(true, true, 0, 16, 16, phase).unwrap_err();
            assert!(e.contains("whitelist"), "{e}");
        }
    }

    #[test]
    fn prepare_refuses_without_the_driver_and_commit_without_listeners() {
        assert!(plan(true, false, 1, 0, 0, Phase::Prepare).is_err(), "no driver ⇒ no route");
        assert!(plan(true, true, 1, 0, 0, Phase::Commit).is_err(), "no listeners ⇒ the driver would redirect to closed ports");
        // ...and each phase ignores the OTHER phase's precondition, which is what makes
        // the two-call order explicit rather than accidental
        assert!(plan(true, true, 1, 0, 0, Phase::Commit).unwrap_err().contains("TCP"));
        assert!(
            plan(true, false, 1, 16, 16, Phase::Commit).is_ok(),
            "commit does not re-ask about the driver: prepare() already did"
        );
    }

    #[test]
    fn a_route_without_udp_listeners_is_refused_by_name() {
        // The driver draws UDP flows from a SEPARATE pool (one token per flow), so a
        // commit that only has TCP listeners would drop every datagram on the floor.
        let e = plan(true, true, 1, 16, 0, Phase::Commit).unwrap_err();
        assert!(e.contains("UDP"), "{e}");
        let e = plan(true, true, 1, 0, 16, Phase::Commit).unwrap_err();
        assert!(e.contains("TCP"), "{e}");
    }

    #[test]
    fn a_happy_plan_counts_one_filter_pair_per_app() {
        assert_eq!(plan(true, true, 1, 16, 16, Phase::Commit).unwrap(), 4);
        assert_eq!(plan(true, true, 3, 16, 16, Phase::Commit).unwrap(), 12);
    }

    #[test]
    fn scoped_apps_matches_the_cli_preview_rules() {
        let mut c = Config::default();
        c.settings.app_whitelist = vec!["  a.exe ".into(), "".into(), "\t".into(), "b.exe".into()];
        assert_eq!(scoped_apps(&c), vec!["a.exe".to_string(), "b.exe".to_string()]);
        // trimming happens here, so a whitelist of blanks still cannot mean "everything"
        c.settings.app_whitelist = vec!["   ".into()];
        assert!(scoped_apps(&c).is_empty());
        assert!(plan(true, true, scoped_apps(&c).len(), 16, 16, Phase::Commit).is_err());
    }
}
