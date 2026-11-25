//! `tpwfp` — the classify seam a future WFP callout DRIVER is built around.
//!
//! HONEST STATUS:
//!   * The DECISION LOGIC is the shared, unit-tested
//!     `trans_proxier::wfp_classify::classify`, plus the `remote_from_sockaddr`
//!     parser below (both tested here / in the main crate).
//!   * The ABI constants and structs come from `trans_proxier::wfp`, which mirrors
//!     the installed Windows SDK headers; nothing here re-declares a FWP constant by
//!     hand any more (an earlier draft had PERMIT/BLOCK wrong by an action-flag bit).
//!   * This crate is NOT a loadable callout and never was: the BFE loads callouts
//!     from a kernel driver only (`FwpsCalloutRegister1` lives in `fwpkclnt.lib`),
//!     and no user-mode DLL is ever handed a classify callback. What ships here is
//!     the pure part — parse, decide, and the [`FlowRecord`] layout the driver must
//!     stash so the engine can recover each flow's ORIGINAL destination.
//!   * `Classify` below is a structurally correct, COMPILE-VERIFIED skeleton that
//!     returns PERMIT (pass-through). Wiring the redirect needs the WDK's
//!     `fwpsk.h` (not installed in this workspace) plus a live elevated BFE: a wrong
//!     redirect silently breaks networking, which this project refuses to ship as
//!     "done". See `docs/WFP_ROADMAP.md`.
//!
//! What the driver author must supply, in order:
//!   1. `FwpsCalloutRegister1` for `Classify`/`Notify`/`FlowDelete` under
//!      [`CALLOUT_KEY`] — the same GUID `trans_proxier::wfp` puts into its filters.
//!   2. In `Classify`: read the remote `SOCKADDR*` + pid from the incoming
//!      values/metadata, `remote_from_sockaddr` -> host, `classify_decision` ->
//!      verdict, then `FwpsAllocateCloneNetBufferList`-free redirect: set the layer
//!      output to the local engine endpoint and record a [`FlowRecord`] on the flow
//!      context (`FwpsFlowAssociateContext0`) for the accept side to look up.
//!   3. `FwpsCalloutUnregisterById0` on unload; filters are removed by the user-mode
//!      side (dynamic session) when the app exits.

#![cfg(windows)]
#![allow(non_camel_case_types, dead_code)]

use std::ffi::c_void;

// --- shared, TESTED core comes from the main crate --------------------------
pub use trans_proxier::wfp_classify::{
    classify as classify_decision, FlowRecord, WfpVerdict, FLOW_RECORD_LEN, VERDICT_BLOCK,
    VERDICT_PERMIT, VERDICT_REDIRECT,
};
// Single source of truth for the WFP ABI: these mirror the SDK headers and are
// pinned by tests in `trans_proxier::wfp`.
pub use trans_proxier::wfp::{
    FWP_ACTION_BLOCK, FWP_ACTION_CALLOUT_TERMINATING, FWP_ACTION_PERMIT,
    LAYER_ALE_CONNECT_REDIRECT_V4, LAYER_ALE_CONNECT_REDIRECT_V6, REDIRECT_CALLOUT as CALLOUT_KEY,
};

const AF_INET: u16 = 2;
const AF_INET6: u16 = 23;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SockAddrIn {
    pub sin_family: u16,
    pub sin_port_be: u16, // network byte order
    pub sin_addr: [u8; 4],
    pub sin_zero: [u8; 8],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SockAddrIn6 {
    pub sin6_family: u16,
    pub sin6_port_be: u16,
    pub sin6_flowinfo: u32,
    pub sin6_addr: [u8; 16],
    pub sin6_scope_id: u32,
}

/// Parse a WFP `SOCKADDR*` (as raw bytes) into (address-bytes, port-host-order).
/// Pure + unit-tested: this is the part of the classify path that is safe to
/// verify without a BFE. Returns None for unrecognised families.
pub fn remote_from_sockaddr(bytes: &[u8]) -> Option<(Vec<u8>, u16)> {
    if bytes.len() >= std::mem::size_of::<SockAddrIn>() {
        let sa = unsafe { &*(bytes.as_ptr() as *const SockAddrIn) };
        match sa.sin_family {
            AF_INET => return Some((sa.sin_addr.to_vec(), u16::from_be(sa.sin_port_be))),
            AF_INET6 => {
                if bytes.len() >= std::mem::size_of::<SockAddrIn6>() {
                    let sa6 = unsafe { &*(bytes.as_ptr() as *const SockAddrIn6) };
                    return Some((sa6.sin6_addr.to_vec(), u16::from_be(sa6.sin6_port_be)));
                }
            }
            _ => {}
        }
    }
    None
}

// --- FFI callout surface (structurally correct; COMPILE-VERIFIED ONLY) ------
// The real classifyFn receives `*const FWPS_INCOMING_VALUES0`,
// `*const FWPS_INCOMING_METADATA_VALUES0`, the classify-context pointers, and
// returns a `FWP_ACTION_TYPE`. We keep every WFP pointer OPAQUE (`c_void`) so
// the shim compiles against no fragile struct layouts, and default to PERMIT
// (pass-through) — this can NEVER alter real traffic until the redirect path is
// verified on a live BFE.

/// `classifyFn` — the driver registers this under [`CALLOUT_KEY`].
/// Intended (to-be-verified on a live BFE) body: read the remote sockaddr + pid
/// from the incoming values, parse with `remote_from_sockaddr`, ask
/// `classify_decision(...)`, and on `Redirect{chain}` emit the redirect action for
/// the local engine endpoint while stashing a `FlowRecord` on the flow context.
#[unsafe(no_mangle)]
pub extern "system" fn Classify(
    in_fixed_values: *const c_void,
    in_meta: *const c_void,
    _out_type: u32,
    out_classify_header: *mut c_void,
) -> u32 {
    // Silence unused for the compile-only skeleton while keeping the shape real.
    let _ = (in_fixed_values, in_meta, out_classify_header);
    // TODO(live-BFE): implement the redirect action after verifying the
    // FWPS_INCOMING_VALUES0 field indices against the installed fwpsk.h. Until
    // then pass everything through — a wrong redirect is worse than none.
    FWP_ACTION_PERMIT
}

/// `notifyFn` — callout lifetime notifications (add/delete). No state to tear
/// down in the safe-default skeleton.
#[unsafe(no_mangle)]
pub extern "system" fn Notify(_notify_type: u32, _reserved: *const c_void, _context: u64) {}

/// `flowDeleteFn` — per-flow teardown. Nothing allocated per-flow yet.
#[unsafe(no_mangle)]
pub extern "system" fn FlowDelete(_flow_context: *const c_void, _context: u64) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_sockaddr_with_network_port() {
        let sa = SockAddrIn {
            sin_family: AF_INET,
            sin_port_be: 443u16.to_be(),
            sin_addr: [93, 184, 216, 34],
            sin_zero: [0; 8],
        };
        let bytes = unsafe {
            std::slice::from_raw_parts(&sa as *const SockAddrIn as *const u8, std::mem::size_of::<SockAddrIn>())
        };
        let (ip, port) = remote_from_sockaddr(bytes).expect("v4 parsed");
        assert_eq!(ip, vec![93, 184, 216, 34]);
        assert_eq!(port, 443, "port converted from network to host order");
    }

    #[test]
    fn parses_ipv6_sockaddr() {
        let mut sa6 = SockAddrIn6 {
            sin6_family: AF_INET6,
            sin6_port_be: 53u16.to_be(),
            sin6_flowinfo: 0,
            sin6_addr: [0; 16],
            sin6_scope_id: 0,
        };
        sa6.sin6_addr[15] = 1; // ::1
        let bytes = unsafe {
            std::slice::from_raw_parts(&sa6 as *const SockAddrIn6 as *const u8, std::mem::size_of::<SockAddrIn6>())
        };
        let (ip, port) = remote_from_sockaddr(bytes).expect("v6 parsed");
        assert_eq!(ip.len(), 16);
        assert_eq!(ip[15], 1);
        assert_eq!(port, 53);
    }

    #[test]
    fn rejects_unknown_family_and_short_buffers() {
        assert!(remote_from_sockaddr(&[]).is_none());
        let mut bogus = [0u8; 16];
        bogus[0] = 99; // bogus family
        bogus[1] = 0;
        assert!(remote_from_sockaddr(&bogus).is_none());
    }

    #[test]
    fn classify_defaults_to_permit_safe() {
        // The compile-only skeleton MUST pass traffic through (never redirect)
        // until the redirect path is verified on a live BFE.
        let rc = Classify(std::ptr::null(), std::ptr::null(), 0, std::ptr::null_mut());
        assert_eq!(rc, FWP_ACTION_PERMIT);
    }
    /// The action codes a driver writes into `classifyOut->actionType` must be the
    /// platform's, not hand-guessed: these re-exports are pinned in the main crate,
    /// and the values are asserted here so a regression in either crate is caught.
    #[test]
    fn action_codes_come_from_the_sdk_mirror() {
        assert_eq!(FWP_ACTION_PERMIT, 0x1002, "fwptypes.idl: FWP_ACTION_PERMIT");
        assert_eq!(FWP_ACTION_BLOCK, 0x1001, "fwptypes.idl: FWP_ACTION_BLOCK");
        assert_eq!(FWP_ACTION_CALLOUT_TERMINATING, 0x5003);
    }

    #[test]
    fn parsed_sockaddr_fills_the_flow_record() {
        // glue: the classify-side parser and the driver/engine record agree
        let sa = SockAddrIn {
            sin_family: AF_INET,
            sin_port_be: 53u16.to_be(),
            sin_addr: [8, 8, 8, 8],
            sin_zero: [0; 8],
        };
        let raw = unsafe {
            std::slice::from_raw_parts(&sa as *const SockAddrIn as *const u8, std::mem::size_of::<SockAddrIn>())
        };
        let (addr, port) = remote_from_sockaddr(raw).expect("parse v4 sockaddr");
        let mut rec = FlowRecord {
            family: AF_INET,
            port_be: port.to_be(),
            addr: [0u8; 16],
            pid: 7,
            chain: 2,
            verdict: VERDICT_REDIRECT,
            proto: 17,
            flow_id: 55,
            local_addr: [0; 16],
            local_port_be: 0,
            token_port: 12007,
        };
        rec.addr[..4].copy_from_slice(&addr);
        let back = FlowRecord::from_bytes(&rec.to_bytes()).expect("record survives the boundary");
        assert_eq!(back.remote(), Some("8.8.8.8:53".parse().unwrap()));
        assert_eq!(back.verdict, VERDICT_REDIRECT);
        assert_eq!(back.token_port, 12007, "the token survives the kernel boundary too");
        assert_ne!(VERDICT_PERMIT, VERDICT_BLOCK);
        assert_eq!(FLOW_RECORD_LEN, 72);
    }
}
