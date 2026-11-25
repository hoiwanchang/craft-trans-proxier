//! `wfp_ingress::enabled()` is the door the whole WFP route walks through: the engine
//! binds its TCP and UDP token ports only when it answers true. Reading the environment
//! once into a `OnceLock` is right for the CLI (`TPROXIER_WFP_INGRESS=1` is set before
//! `main` gets going) but the GUI decides when the operator ticks a box, which can be
//! after something already asked. This test lives in its OWN binary because the flag is
//! process-global and one-way: asserting it here cannot leak into the other suites.
#![cfg(windows)]

#[test]
fn the_ingress_path_can_be_armed_from_inside_the_process() {
    // Nothing in this process set the environment variable, so the route starts closed.
    // If that ever stops being true, this precondition is what to look at first: the
    // rest of the test would be proving nothing.
    assert!(
        std::env::var_os("TPROXIER_WFP_INGRESS").is_none(),
        "this test must run with the environment door closed to prove the runtime one works"
    );
    assert!(!trans_proxier::wfp_ingress::enabled(), "closed before enable_at_runtime()");

    trans_proxier::wfp_ingress::enable_at_runtime();
    assert!(trans_proxier::wfp_ingress::enabled(), "open after enable_at_runtime()");

    // One-way: asking again is a no-op, never a toggle. Turning the route off means
    // dropping the Route guard (which disarms the driver), not flipping this flag.
    trans_proxier::wfp_ingress::enable_at_runtime();
    assert!(trans_proxier::wfp_ingress::enabled(), "stays open — it is not a toggle");
}
