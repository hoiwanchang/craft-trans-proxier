//! Update-check feature (fnd_13: "Check for Product Updates on Startup",
//! Settings.ini `UpdateCheck` / `UpdateCheckUrl`).
//!
//! This is the *decision* half of the feature, kept pure + fully unit-tested:
//! it compares a current version against a "latest" version and says whether an
//! update is available. The *fetch* half (GET `UpdateCheckUrl`) is deliberately
//! left to the caller — this module never invents a network endpoint (there is
//! no real update server for a clean-room replica) and performs no I/O, so the
//! behaviour is verifiable without a network side effect.

/// A dotted numeric version, e.g. "2.1.0". Non-numeric / missing parts are 0.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version(pub [u32; 3]);

impl Version {
    pub fn parse(s: &str) -> Version {
        let mut parts = [0u32; 3];
        for (i, p) in s.trim().trim_start_matches('v').split('.').take(3).enumerate() {
            parts[i] = p.trim().parse::<u32>().unwrap_or(0);
        }
        Version(parts)
    }
}

impl std::cmp::Ord for Version {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}
impl std::cmp::PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Outcome of an update check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateOutcome {
    /// A newer version exists.
    Available { latest: String },
    /// Already up to date.
    UpToDate,
    /// Checking disabled (`UpdateCheck` off) or not configured.
    Disabled,
}

/// Pure comparison: is `latest` newer than `current`?
pub fn update_available(current: &str, latest: &str) -> bool {
    Version::parse(latest) > Version::parse(current)
}

/// The startup decision, honouring the `UpdateCheck` setting. `latest` is the
/// value the caller fetched from `UpdateCheckUrl` (None => not fetched / off).
pub fn check(current: &str, enabled: bool, latest: Option<&str>) -> UpdateOutcome {
    if !enabled {
        return UpdateOutcome::Disabled;
    }
    match latest {
        Some(l) if update_available(current, l) => UpdateOutcome::Available { latest: l.to_string() },
        Some(_) => UpdateOutcome::UpToDate,
        None => UpdateOutcome::Disabled,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_parses_and_orders() {
        assert!(Version::parse("1.2.3") < Version::parse("1.2.4"));
        assert!(Version::parse("2.0.0") > Version::parse("1.99.99"));
        assert_eq!(Version::parse("1.2"), Version::parse("1.2.0"));
        assert_eq!(Version::parse("v3.1"), Version::parse("3.1.0"));
        // non-numeric segment degrades to 0, doesn't panic
        assert_eq!(Version::parse("1.x.3"), Version::parse("1.0.3"));
    }

    #[test]
    fn detects_newer_and_equal_and_older() {
        assert!(update_available("1.0.0", "1.0.1"));
        assert!(!update_available("1.0.1", "1.0.1"));
        assert!(!update_available("1.1.0", "1.0.9"), "inverse: older 'latest' is not an update");
    }

    #[test]
    fn disabled_setting_short_circuits() {
        assert_eq!(check("1.0.0", false, Some("9.9.9")), UpdateOutcome::Disabled);
        // enabled but not fetched -> Disabled (no fabricated result)
        assert_eq!(check("1.0.0", true, None), UpdateOutcome::Disabled);
    }

    #[test]
    fn available_and_uptodate_outcomes() {
        assert_eq!(check("1.0.0", true, Some("1.2.0")), UpdateOutcome::Available { latest: "1.2.0".into() });
        assert_eq!(check("1.2.0", true, Some("1.2.0")), UpdateOutcome::UpToDate);
    }
}
