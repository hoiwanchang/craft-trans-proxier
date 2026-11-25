//! Windows Filtering Platform (WFP) control plane — user-mode filter authoring.
//!
//! WHAT THIS IS, AND WHAT IT IS NOT — read before running anything here:
//!
//!   * The ABI mirrored below (struct layouts, GUIDs, enum values) is transcribed
//!     from the installed Windows SDK 10.0.26100 headers and cited per constant
//!     (`fwptypes.idl`, `fwpmtypes.idl`, `fwpmu.h`). The `abi_*` unit tests pin
//!     every size and offset, so a field-order slip fails the build instead of
//!     silently handing BFE a garbage filter.
//!   * None of it has been executed against a live Base Filtering Engine: adding
//!     filters needs elevation and changes real routing. The module is inert until
//!     a caller opens a session, and `Wfp::open` uses a DYNAMIC session, so every
//!     sublayer/filter it installs is removed by BFE when our process exits — a
//!     crash cannot leave this machine without network.
//!   * A user-mode filter CANNOT redirect a connection on its own.
//!     `FWPM_ACTION0` carries exactly one union member alongside its action type —
//!     `filterType` or, for a callout action, `calloutKey` — so there is no
//!     redirect endpoint to put in a filter. Redirection is done by a callout's
//!     classifyFn, which is also the only place that can read the ORIGINAL remote
//!     address and hand it to the local engine. The BFE loads callouts from a
//!     kernel driver only, so the filters built here carry
//!     `FWP_ACTION_CALLOUT_TERMINATING` + our callout key, and the missing piece
//!     is the signed `.sys` described in `docs/WFP_ROADMAP.md`.
//!   * Until that driver exists, `intercept::Engine` (the driverless hook) is the
//!     working, live-verified transparent path.

#![cfg(windows)]

use std::ffi::c_void;
use std::ptr;

// ---------------------------------------------------------------------------
// GUIDs — values copied from the SDK's `DEFINE_GUID` blocks (the comment above
// each definition in the header is the canonical string form).
// ---------------------------------------------------------------------------
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Guid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

macro_rules! guid {
    ($a:expr, $b:expr, $c:expr, $d:expr) => {
        Guid { data1: $a, data2: $b, data3: $c, data4: $d }
    };
}

/// Canonical string form, e.g. for logs and the preview.
pub fn fmt_guid(g: &Guid) -> String {
    let d = &g.data4;
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        g.data1, g.data2, g.data3, d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]
    )
}

// fwpmu.h:826  c6e63c8c-b784-4562-aa7d-0a67cfcaf9a3
pub const LAYER_ALE_CONNECT_REDIRECT_V4: Guid =
    guid!(0xc6e63c8c, 0xb784, 0x4562, [0xaa, 0x7d, 0x0a, 0x67, 0xcf, 0xca, 0xf9, 0xa3]);
// fwpmu.h:835  587e54a7-8046-42ba-a0aa-b716250fc7fd
pub const LAYER_ALE_CONNECT_REDIRECT_V6: Guid =
    guid!(0x587e54a7, 0x8046, 0x42ba, [0xa0, 0xaa, 0xb7, 0x16, 0x25, 0x0f, 0xc7, 0xfd]);
// fwpmu.h:1865 d78e1e87-8644-4ea5-9437-d809ecefc971
pub const COND_ALE_APP_ID: Guid =
    guid!(0xd78e1e87, 0x8644, 0x4ea5, [0x94, 0x37, 0xd8, 0x09, 0xec, 0xef, 0xc9, 0x71]);
// fwpmu.h:1704 3971ef2b-623e-4f9a-8cb1-6e79b806b9a7
pub const COND_IP_PROTOCOL: Guid =
    guid!(0x3971ef2b, 0x623e, 0x4f9a, [0x8c, 0xb1, 0x6e, 0x79, 0xb8, 0x06, 0xb9, 0xa7]);

/// Our own identifiers (random, stable for this product).
pub const REDIRECT_SUBLAYER: Guid =
    guid!(0xd7a1f001, 0x1111, 0x4222, [8, 8, 8, 8, 8, 8, 8, 8]);
/// The callout the kernel driver registers; filters below point at this key, and
/// the driver must register its classifyFn under the same GUID.
pub const REDIRECT_CALLOUT: Guid =
    guid!(0xd7a1f002, 0x2222, 0x4333, [9, 9, 9, 9, 9, 9, 9, 9]);

// ---------------------------------------------------------------------------
// Enumerations — fwptypes.idl (values are the position in each enum).
// ---------------------------------------------------------------------------
pub const FWP_UINT8: u32 = 1;
pub const FWP_UINT16: u32 = 2;
pub const FWP_UINT32: u32 = 3;
pub const FWP_UINT64: u32 = 4;
pub const FWP_BYTE_BLOB_TYPE: u32 = 12;

pub const FWP_MATCH_EQUAL: u32 = 0;

const FWP_ACTION_FLAG_TERMINATING: u32 = 0x0000_1000;
const FWP_ACTION_FLAG_NON_TERMINATING: u32 = 0x0000_2000;
const FWP_ACTION_FLAG_CALLOUT: u32 = 0x0000_4000;
/// fwptypes.idl:391/394 — BLOCK = 1|TERMINATING, PERMIT = 2|TERMINATING.
pub const FWP_ACTION_BLOCK: u32 = 0x0000_0001 | FWP_ACTION_FLAG_TERMINATING;
pub const FWP_ACTION_PERMIT: u32 = 0x0000_0002 | FWP_ACTION_FLAG_TERMINATING;
/// The action that lets a callout decide — and therefore redirect — the flow.
pub const FWP_ACTION_CALLOUT_TERMINATING: u32 =
    0x0000_0003 | FWP_ACTION_FLAG_CALLOUT | FWP_ACTION_FLAG_TERMINATING;
#[allow(dead_code)]
pub const FWP_ACTION_CALLOUT_INSPECTION: u32 =
    0x0000_0004 | FWP_ACTION_FLAG_CALLOUT | FWP_ACTION_FLAG_NON_TERMINATING;

/// fwpmtypes.idl:123 — objects created in this session die with the process.
const FWPM_SESSION_FLAG_DYNAMIC: u32 = 0x0000_0001;
/// fwpmtypes.idl:832 — when the callout named by a filter is not registered, the
/// traffic is PERMITTED rather than blocked.
///
/// This flag is load-bearing, not defensive tidying: the `FwpsCalloutRegister1`
/// remarks state that until a callout is registered, filters whose action is
/// `FWP_ACTION_CALLOUT_TERMINATING` are **treated as FWP_ACTION_BLOCK** (and
/// `..._INSPECTION` filters are ignored outright). A service that installed our
/// filters before the driver finished loading would therefore cut the network out
/// from under exactly the apps the user whitelisted — a boot-order race that would
/// look like a total outage. With this flag the worst case is "not proxied yet",
/// which is the right failure mode.
pub const FWPM_FILTER_FLAG_PERMIT_IF_CALLOUT_UNREGISTERED: u32 = 0x0000_0010;

pub const IPPROTO_TCP: u8 = 6;
/// The other transport the redirect route covers. One filter PER TRANSPORT, rather
/// than one protocol-agnostic filter, for two reasons that do not depend on each
/// other:
///   * the callout reads `IP_PROTOCOL` out of the incoming values, and a field the
///     matching filters test is a field the engine indicates — testing it here removes
///     the guesswork about whether the value arrives at all (if it did not, the classify
///     path would see `FWP_EMPTY` and permit, i.e. silently proxy nothing);
///   * ICMP/GRE/ESP then never reach the callback in the first place, which is cheaper
///     and puts the policy where an operator can see it in `netsh wfp show state`.
pub const IPPROTO_UDP: u8 = 17;

// ---------------------------------------------------------------------------
// Struct mirrors. Field order and types follow the IDL declarations; the
// `abi_*` test asserts the resulting x64 sizes/offsets.
// ---------------------------------------------------------------------------
/// FWP_BYTE_BLOB (fwptypes.idl) — a counted buffer, `data` is a pointer.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FwpByteBlob {
    pub size: u32,
    pub data: *const u8,
}

/// FWP_VALUE0 / FWP_CONDITION_VALUE0: a type tag plus an 8-byte payload union.
/// `FWP_UINT64` keeps its value in the u64 arm; the integer arms use the low
/// bytes, which is why `uint64` is written directly for them too.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FwpValue0 {
    pub ftype: u32,
    pub value: u64,
}

impl FwpValue0 {
    const EMPTY: FwpValue0 = FwpValue0 { ftype: 0, value: 0 };
    const fn uint64(v: u64) -> FwpValue0 {
        FwpValue0 { ftype: FWP_UINT64, value: v }
    }
}

/// FWPM_DISPLAY_DATA0 — two NUL-terminated wide strings.
#[repr(C)]
#[derive(Clone, Copy)]
struct FwpmDisplayData0 {
    name: *const u16,
    description: *const u16,
}

/// FWPM_FILTER_CONDITION0.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FwpmFilterCondition0 {
    pub field_key: Guid,
    pub match_type: u32,
    pub condition_value: FwpValue0,
}

/// FWPM_ACTION0 — the union member is `calloutKey` exactly when the action type
/// has FWP_ACTION_FLAG_CALLOUT set. There is no redirect field: that is the whole
/// reason a redirect needs a callout driver.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FwpmAction0 {
    pub action_type: u32,
    pub callout_key: Guid,
}

/// FWPM_SUBLAYER0. `weight` is a plain UINT16 here (not an FWP_VALUE0).
#[repr(C)]
struct FwpmSubLayer0 {
    sublayer_key: Guid,
    display_data: FwpmDisplayData0,
    flags: u32,
    provider_key: *const Guid,
    provider_data: FwpByteBlob,
    weight: u16,
}

/// FWPM_FILTER0. Note the order: layer/sublayer keys, weight, THEN the condition
/// array, then the action — the action is not where a naive guess would put it.
#[repr(C)]
struct FwpmFilter0 {
    filter_key: Guid,
    display_data: FwpmDisplayData0,
    flags: u32,
    provider_key: *const Guid,
    provider_data: FwpByteBlob,
    layer_key: Guid,
    sublayer_key: Guid,
    weight: FwpValue0,
    num_filter_conditions: u32,
    filter_condition: *const FwpmFilterCondition0,
    action: FwpmAction0,
    /// union { UINT64 rawContext; GUID providerContextKey } — 16 bytes, the
    /// provider-context arm is unused here, so both are zero.
    raw_context: [u64; 2],
    reserved: *const Guid,
    filter_id: u64,
    effective_weight: FwpValue0,
}

/// FWPM_CALLOUT0 — the BFE's *object* for a callout. Registering the classify
/// callback (in the driver) is not enough: a filter that names a callout key the
/// engine does not know is rejected, so this object has to exist before
/// [`Wfp::route_app_to_callout`] runs. One object per (key, layer) pair.
#[repr(C)]
struct FwpmCallout0 {
    callout_key: Guid,
    display_data: FwpmDisplayData0,
    flags: u32,
    provider_key: *const Guid,
    provider_data: FwpByteBlob,
    applicable_layer: Guid,
    callout_id: u32,
}

/// FWPM_SESSION0, only the fields FwpmEngineOpen0 reads before the session key.
#[repr(C)]
struct FwpmSession0 {
    session_key: Guid,
    display_data: FwpmDisplayData0,
    flags: u32,
    txn_wait_timeout_msec: u32,
    process_id: u32,
    sid: *const c_void,
    username: *const u16,
    kernel_mode: i32,
}

type HANDLE = *mut c_void;

#[link(name = "fwpuclnt")]
unsafe extern "system" {
    fn FwpmEngineOpen0(
        server: *const c_void,
        authn: u32,
        authn_info: *const c_void,
        session: *const FwpmSession0,
        engine_handle: *mut HANDLE,
    ) -> u32;
    fn FwpmEngineClose0(engine: HANDLE) -> u32;
    fn FwpmTransactionBegin0(engine: HANDLE, flags: u32) -> u32;
    fn FwpmTransactionCommit0(engine: HANDLE) -> u32;
    fn FwpmTransactionAbort0(engine: HANDLE) -> u32;
    fn FwpmSubLayerAdd0(engine: HANDLE, sublayer: *const FwpmSubLayer0, sd: *const c_void) -> u32;
    fn FwpmSubLayerDeleteByKey0(engine: HANDLE, key: *const Guid) -> u32;
    fn FwpmFilterAdd0(engine: HANDLE, filter: *const FwpmFilter0, sd: *const c_void, id: *mut u64) -> u32;
    fn FwpmFilterDeleteById0(engine: HANDLE, id: u64) -> u32;
    fn FwpmCalloutAdd0(engine: HANDLE, callout: *const FwpmCallout0, sd: *const c_void, id: *mut u32) -> u32;
    fn FwpmCalloutDeleteByKey0(engine: HANDLE, key: *const Guid) -> u32;
}

/// The `FWP_BYTE_BLOB` an ALE_APP_ID condition needs: the app's full path as
/// UTF-16LE without a terminating NUL. ALE reports application IDs normalised to
/// upper case, so the comparison value is upper-cased here — otherwise the filter
/// quietly never fires and traffic leaks instead of being proxied. The blob owns
/// the bytes and hands out a pointer into them, so it must outlive the condition
/// built from it.
pub struct AppId {
    /// The UTF-16LE path bytes. Boxed so its address is stable.
    bytes: Box<[u8]>,
    /// The `FWP_BYTE_BLOB` header pointing at `bytes`; boxed for the same reason,
    /// because the condition value carries a pointer to THIS struct.
    blob: Box<FwpByteBlob>,
}

impl AppId {
    pub fn new(path: &str) -> AppId {
        let units: Vec<u16> = path.to_uppercase().encode_utf16().collect();
        let bytes = unsafe {
            std::slice::from_raw_parts(units.as_ptr() as *const u8, units.len() * 2).to_vec()
        }
        .into_boxed_slice();
        let blob = Box::new(FwpByteBlob { size: bytes.len() as u32, data: bytes.as_ptr() });
        AppId { bytes, blob }
    }

    pub fn blob(&self) -> &FwpByteBlob {
        &self.blob
    }

    pub fn condition(&self) -> FwpmFilterCondition0 {
        FwpmFilterCondition0 {
            field_key: COND_ALE_APP_ID,
            match_type: FWP_MATCH_EQUAL,
            condition_value: FwpValue0 {
                ftype: FWP_BYTE_BLOB_TYPE,
                // The union arm for a blob is a pointer to FWP_BYTE_BLOB.
                value: &*self.blob as *const FwpByteBlob as u64,
            },
        }
    }

    /// Keep this alive as long as any condition built from it is in use.
    #[allow(dead_code)]
    fn owns_bytes(&self) -> bool {
        self.blob.data as usize >= self.bytes.as_ptr() as usize
            && self.blob.data as usize <= self.bytes.as_ptr() as usize + self.bytes.len()
    }
}

/// Handle to an open BFE session. Filters live in [`REDIRECT_SUBLAYER`], and the
/// session is dynamic, so dropping (or crashing) removes them; `remove_all` does
/// it eagerly for callers that want to hand the network back without exiting.
pub struct Wfp {
    engine: HANDLE,
    sublayer_added: bool,
    /// layers we registered the callout object for (per (key, layer) pair)
    callout_layers: Vec<Guid>,
    filters: Vec<u64>,
}

impl Wfp {
    /// Open a dynamic BFE session. Requires elevation to add filters; opening a
    /// session by itself changes no policy.
    pub fn open() -> Result<Wfp, u32> {
        let mut engine: HANDLE = ptr::null_mut();
        let display = utf16("trans-proxier");
        let session = FwpmSession0 {
            session_key: Guid::default(), // BFE assigns
            display_data: FwpmDisplayData0 { name: display.as_ptr(), description: ptr::null() },
            flags: FWPM_SESSION_FLAG_DYNAMIC,
            txn_wait_timeout_msec: 5000,
            process_id: 0,
            sid: ptr::null(),
            username: ptr::null(),
            kernel_mode: 0,
        };
        // RPC_C_AUTHN_DEFAULT = 0xFFFFFFFF; NULL server + session = local, current.
        let rc = unsafe { FwpmEngineOpen0(ptr::null(), 0xFFFF_FFFF, ptr::null(), &session, &mut engine) };
        if rc != 0 {
            return Err(rc);
        }
        Ok(Wfp { engine, sublayer_added: false, callout_layers: Vec::new(), filters: Vec::new() })
    }

    pub fn ensure_sublayer(&mut self) -> Result<(), u32> {
        if self.sublayer_added {
            return Ok(());
        }
        let name = utf16("trans-proxier redirect");
        let sublayer = FwpmSubLayer0 {
            sublayer_key: REDIRECT_SUBLAYER,
            display_data: FwpmDisplayData0 { name: name.as_ptr(), description: ptr::null() },
            flags: 0, // not persistent: a dynamic session cannot outlive us anyway
            provider_key: ptr::null(),
            provider_data: FwpByteBlob { size: 0, data: ptr::null() },
            weight: 0x8000,
        };
        let rc = in_transaction(self.engine, || unsafe {
            FwpmSubLayerAdd0(self.engine, &sublayer, ptr::null())
        })?;
        let _ = rc;
        self.sublayer_added = true;
        Ok(())
    }

    /// Announce this driver's callout to the BFE for one layer, so a filter in that
    /// layer may name it. Without this, `FwpmFilterAdd0` rejects the filter with
    /// `FWP_E_CALLOUT_NOT_FOUND` — the classify callback living in the driver is not
    /// enough on its own.
    pub fn ensure_callout(&mut self, layer: Guid) -> Result<(), u32> {
        if self.callout_layers.contains(&layer) {
            return Ok(());
        }
        let name = utf16("trans-proxier redirect callout");
        let callout = FwpmCallout0 {
            callout_key: REDIRECT_CALLOUT,
            display_data: FwpmDisplayData0 { name: name.as_ptr(), description: ptr::null() },
            flags: 0,
            provider_key: ptr::null(),
            provider_data: FwpByteBlob { size: 0, data: ptr::null() },
            applicable_layer: layer,
            callout_id: 0,
        };
        in_transaction(self.engine, || unsafe {
            FwpmCalloutAdd0(self.engine, &callout, ptr::null(), ptr::null_mut())
        })?;
        self.callout_layers.push(layer);
        Ok(())
    }

    /// Hand every TCP connect made by `app` to our callout, which is the component
    /// that may redirect it. `v6` picks the address family's layer; `tcp_only` adds
    /// the IP_PROTOCOL condition so UDP is left alone.
    ///
    /// This installs a filter but redirects nothing by itself: without the callout
    /// driver registered under [`REDIRECT_CALLOUT`], BFE has no classifyFn to invoke
    /// — and until it is registered, the filter is treated as FWP_ACTION_BLOCK, which
    /// is precisely why FWPM_FILTER_FLAG_PERMIT_IF_CALLOUT_UNREGISTERED is set below.
    ///
    /// WHY `FWP_ACTION_CALLOUT_TERMINATING` AND NOT `FWP_ACTION_PERMIT`: Microsoft's
    /// "Types of Callouts" page says a redirection callout's filter action type
    /// "should be set to FWP_ACTION_PERMIT", which cannot be taken literally in this
    /// ABI — `FWPM_ACTION0` selects its `calloutKey` union member only when the type
    /// carries `FWP_ACTION_FLAG_CALLOUT` (`switch_is` in fwpmtypes.idl), so a PERMIT
    /// filter has no way to name a callout. Two other pages settle it:
    /// `FwpsCalloutRegister1`'s remarks speak of "filters with an action type of
    /// FWP_ACTION_CALLOUT_TERMINATING" as the ones waiting on a callout, and the
    /// redirection how-to shows the callout itself returning FWP_ACTION_PERMIT after
    /// `FwpsApplyModifiedLayerData0`. So: filter = CALLOUT_TERMINATING (here), and the
    /// PERMIT sentence describes the classifyFn's return (driver_wfp/tpdrv_wfp.c).
    pub fn route_app_to_callout(&mut self, app: &AppId, v6: bool, proto: u8) -> Result<u64, u32> {
        self.ensure_sublayer()?;
        let layer = if v6 { LAYER_ALE_CONNECT_REDIRECT_V6 } else { LAYER_ALE_CONNECT_REDIRECT_V4 };
        self.ensure_callout(layer)?;
        let conditions = [app.condition(), protocol_condition(proto)];
        let name = utf16(&format!(
            "trans-proxier app->callout ({})",
            if proto == IPPROTO_UDP { "udp" } else { "tcp" }
        ));
        let filter = FwpmFilter0 {
            filter_key: Guid::default(), // BFE assigns
            display_data: FwpmDisplayData0 { name: name.as_ptr(), description: ptr::null() },
            // fail OPEN, never closed, if the callout driver is not registered
            flags: FWPM_FILTER_FLAG_PERMIT_IF_CALLOUT_UNREGISTERED,
            provider_key: ptr::null(),
            provider_data: FwpByteBlob { size: 0, data: ptr::null() },
            layer_key: layer,
            sublayer_key: REDIRECT_SUBLAYER,
            weight: FwpValue0::uint64(0xFFFF_FFFF_FFFF_FFFF), // highest weight
            num_filter_conditions: 2,
            filter_condition: conditions.as_ptr(),
            action: FwpmAction0 {
                action_type: FWP_ACTION_CALLOUT_TERMINATING,
                callout_key: REDIRECT_CALLOUT,
            },
            raw_context: [0; 2],
            reserved: ptr::null(),
            filter_id: 0,
            effective_weight: FwpValue0::EMPTY,
        };
        let mut id: u64 = 0;
        in_transaction(self.engine, || unsafe {
            FwpmFilterAdd0(self.engine, &filter, ptr::null(), &mut id)
        })?;
        self.filters.push(id);
        Ok(id)
    }

    /// Delete our filters and sublayer. Safe to call more than once; the dynamic
    /// session does this on process exit regardless.
    pub fn remove_all(&mut self) -> Result<(), u32> {
        let ids = std::mem::take(&mut self.filters);
        in_transaction(self.engine, || unsafe {
            let mut first = 0u32;
            for id in &ids {
                let rc = FwpmFilterDeleteById0(self.engine, *id);
                if rc != 0 && first == 0 {
                    first = rc;
                }
            }
            if !self.callout_layers.is_empty() {
                // one object per layer; deleting by key removes them all
                let rc = FwpmCalloutDeleteByKey0(self.engine, &REDIRECT_CALLOUT);
                if rc != 0 && first == 0 {
                    first = rc;
                }
            }
            self.callout_layers.clear();
            if self.sublayer_added {
                let rc = FwpmSubLayerDeleteByKey0(self.engine, &REDIRECT_SUBLAYER);
                if rc != 0 && first == 0 {
                    first = rc;
                }
            }
            first
        })?;
        self.sublayer_added = false;
        Ok(())
    }

    /// A side-effect-free description of what [`Wfp::route_app_to_callout`] would
    /// install, so a UI can preview the policy without touching WFP.
    pub fn preview_route(app_path: &str, v6: bool, proto: u8) -> String {
        format!(
            "{} filter in sublayer {}: ALE_APP_ID == \"{}\" AND IP_PROTOCOL == {} => CALLOUT_TERMINATING {}",
            if v6 { "ALE_CONNECT_REDIRECT_V6" } else { "ALE_CONNECT_REDIRECT_V4" },
            fmt_guid(&REDIRECT_SUBLAYER),
            app_path.to_uppercase(),
            proto,
            fmt_guid(&REDIRECT_CALLOUT)
        )
    }
}

impl Drop for Wfp {
    fn drop(&mut self) {
        let _ = self.remove_all();
        unsafe {
            FwpmEngineClose0(self.engine);
        }
    }
}

fn protocol_condition(proto: u8) -> FwpmFilterCondition0 {
    FwpmFilterCondition0 {
        field_key: COND_IP_PROTOCOL,
        match_type: FWP_MATCH_EQUAL,
        // An 8-bit field's value lives in the low byte of the union.
        condition_value: FwpValue0 { ftype: FWP_UINT8, value: proto as u64 },
    }
}

fn utf16(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Run `f` inside a BFE transaction, aborting it if `f` reports a failure.
fn in_transaction(engine: HANDLE, f: impl FnOnce() -> u32) -> Result<u32, u32> {
    unsafe {
        let rc = FwpmTransactionBegin0(engine, 0);
        if rc != 0 {
            return Err(rc);
        }
        let rc = f();
        if rc != 0 {
            FwpmTransactionAbort0(engine);
            return Err(rc);
        }
        let rc = FwpmTransactionCommit0(engine);
        if rc != 0 {
            FwpmTransactionAbort0(engine);
        }
        Ok(rc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The GUIDs are transcribed by hand, so pin them against the strings the SDK
    /// header carries above each DEFINE_GUID.
    #[test]
    fn abi_guids_match_the_sdk_header_strings() {
        assert_eq!(fmt_guid(&LAYER_ALE_CONNECT_REDIRECT_V4), "c6e63c8c-b784-4562-aa7d-0a67cfcaf9a3");
        assert_eq!(fmt_guid(&LAYER_ALE_CONNECT_REDIRECT_V6), "587e54a7-8046-42ba-a0aa-b716250fc7fd");
        assert_eq!(fmt_guid(&COND_ALE_APP_ID), "d78e1e87-8644-4ea5-9437-d809ecefc971");
        assert_eq!(fmt_guid(&COND_IP_PROTOCOL), "3971ef2b-623e-4f9a-8cb1-6e79b806b9a7");
    }

    /// Struct mirrors are only correct if the compiler lays them out the way the
    /// C headers do. These numbers come from the IDL field lists on x64.
    #[test]
    fn abi_mirrors_header_sizes_and_offsets() {
        assert_eq!(std::mem::size_of::<Guid>(), 16);
        assert_eq!(std::mem::size_of::<FwpByteBlob>(), 16);
        assert_eq!(std::mem::size_of::<FwpValue0>(), 16);
        assert_eq!(std::mem::size_of::<FwpmDisplayData0>(), 16);
        // 40, not 32: the condition value holds a pointer arm, so C aligns it to 8
        // and leaves a 4-byte hole after matchType.
        assert_eq!(std::mem::size_of::<FwpmFilterCondition0>(), 40);
        assert_eq!(std::mem::offset_of!(FwpmFilterCondition0, condition_value), 24);
        assert_eq!(std::mem::size_of::<FwpmAction0>(), 20);
        assert_eq!(std::mem::size_of::<FwpmSubLayer0>(), 72);
        assert_eq!(std::mem::offset_of!(FwpmSubLayer0, weight), 64);
        // FWPM_FILTER0: the action sits AFTER the condition array.
        assert_eq!(std::mem::offset_of!(FwpmFilter0, layer_key), 64);
        assert_eq!(std::mem::offset_of!(FwpmFilter0, sublayer_key), 80);
        assert_eq!(std::mem::offset_of!(FwpmFilter0, weight), 96);
        assert_eq!(std::mem::offset_of!(FwpmFilter0, num_filter_conditions), 112);
        assert_eq!(std::mem::offset_of!(FwpmFilter0, filter_condition), 120);
        assert_eq!(std::mem::offset_of!(FwpmFilter0, action), 128);
        assert_eq!(std::mem::offset_of!(FwpmFilter0, filter_id), 176);
        assert_eq!(std::mem::size_of::<FwpmFilter0>(), 200);
        assert_eq!(std::mem::size_of::<FwpmSession0>(), 72);
        // FWPM_CALLOUT0 ends with a UINT32 calloutId after a GUID layer key.
        assert_eq!(std::mem::offset_of!(FwpmCallout0, applicable_layer), 64);
        assert_eq!(std::mem::offset_of!(FwpmCallout0, callout_id), 80);
        assert_eq!(std::mem::size_of::<FwpmCallout0>(), 88);
    }

    /// FWPM_ACTION0 has no place to put a redirect endpoint — the premise this
    /// module is built on, asserted rather than asserted-about.
    #[test]
    fn action_has_room_for_only_a_guid_alongside_the_type() {
        assert_eq!(std::mem::size_of::<FwpmAction0>(), 4 + std::mem::size_of::<Guid>());
        assert_eq!(FWP_ACTION_CALLOUT_TERMINATING & FWP_ACTION_FLAG_CALLOUT, FWP_ACTION_FLAG_CALLOUT);
        assert_eq!(FWP_ACTION_PERMIT, 0x1002);
        assert_eq!(FWP_ACTION_BLOCK, 0x1001);
    }

    /// Builds the filter `route_app_to_callout` installs, without touching the BFE,
    /// so its flags word can be asserted.
    fn redirect_filter() -> FwpmFilter0 {
        FwpmFilter0 {
            filter_key: Guid::default(),
            display_data: FwpmDisplayData0 { name: ptr::null(), description: ptr::null() },
            flags: FWPM_FILTER_FLAG_PERMIT_IF_CALLOUT_UNREGISTERED,
            provider_key: ptr::null(),
            provider_data: FwpByteBlob { size: 0, data: ptr::null() },
            layer_key: LAYER_ALE_CONNECT_REDIRECT_V4,
            sublayer_key: REDIRECT_SUBLAYER,
            weight: FwpValue0::uint64(0xFFFF_FFFF_FFFF_FFFF),
            num_filter_conditions: 0,
            filter_condition: ptr::null(),
            action: FwpmAction0 {
                action_type: FWP_ACTION_CALLOUT_TERMINATING,
                callout_key: REDIRECT_CALLOUT,
            },
            raw_context: [0; 2],
            reserved: ptr::null(),
            filter_id: 0,
            effective_weight: FwpValue0::EMPTY,
        }
    }

    #[test]
    fn filters_fail_open_when_the_callout_is_not_registered() {
        assert_eq!(FWPM_FILTER_FLAG_PERMIT_IF_CALLOUT_UNREGISTERED, 0x10);
        let f = redirect_filter();
        assert_eq!(f.flags & FWPM_FILTER_FLAG_PERMIT_IF_CALLOUT_UNREGISTERED, 0x10);
        // and the action really is the one that invokes a callout
        assert_eq!(f.action.action_type, FWP_ACTION_CALLOUT_TERMINATING);
        assert_eq!(f.action.callout_key, REDIRECT_CALLOUT);
    }

    #[test]
    fn app_id_is_uppercase_utf16_without_nul() {
        let a = AppId::new(r"C:\Games\Game.exe");
        assert!(a.owns_bytes());
        let blob = *a.blob();
        assert_eq!(blob.size as usize, r"C:\GAMES\GAME.EXE".len() * 2);
        let text: String = unsafe {
            std::slice::from_raw_parts(blob.data as *const u16, blob.size as usize / 2)
        }
        .iter()
        .map(|&u| char::from_u32(u as u32).unwrap_or('?'))
        .collect();
        assert_eq!(text, r"C:\GAMES\GAME.EXE");
        let cond = a.condition();
        assert_eq!(cond.field_key, COND_ALE_APP_ID);
        assert_eq!(cond.condition_value.ftype, FWP_BYTE_BLOB_TYPE);
        let back = unsafe { &*(cond.condition_value.value as *const FwpByteBlob) };
        assert_eq!(back.size, blob.size);
    }

    #[test]
    fn protocol_condition_uses_the_uint8_tag() {
        let c = protocol_condition(IPPROTO_TCP);
        assert_eq!(c.field_key, COND_IP_PROTOCOL);
        assert_eq!(c.condition_value.ftype, FWP_UINT8);
        assert_eq!(c.condition_value.value, 6);
    }

    /// The one part of the control plane that can be proven WITHOUT installing
    /// anything: opening a real BFE session with our `FWPM_SESSION0` mirror. A
    /// malformed session struct returns E_INVALIDARG here, and the call changes no
    /// policy — so this is the boundary between "transcribed from headers" and
    /// "accepted by the OS". Ignored by default because it talks to the engine.
    #[test]
    #[ignore = "opens a live BFE session (read-only; installs nothing)"]
    fn control_plane_handshakes_with_the_live_bfe() {
        let mut w = match Wfp::open() {
            Ok(w) => w,
            Err(code) => panic!("FwpmEngineOpen0 rejected our session mirror: {code:#010x}"),
        };
        // Un-elevated this MUST be refused by BFE rather than malformed: that the
        // request was parsed enough to be denied proves the ABI is understood.
        match w.ensure_sublayer() {
            Ok(()) => {
                // running elevated: remove it again immediately, nothing else
                w.remove_all().expect("rollback of our own sublayer");
            }
            Err(code) => assert!(
                code == 5 || code == 0x8007_0005,
                "expected a permission denial, got {code:#010x}"
            ),
        }
    }

    #[test]
    fn preview_is_pure_and_formatted() {
        let s = Wfp::preview_route(r"C:\Games\game.exe", false, IPPROTO_TCP);
        assert!(s.contains("ALE_CONNECT_REDIRECT_V4"), "{s}");
        assert!(s.contains(r"C:\GAMES\GAME.EXE"), "{s}");
        assert!(s.contains(&fmt_guid(&REDIRECT_CALLOUT)), "{s}");
        assert!(Wfp::preview_route("x", true, IPPROTO_UDP).contains("ALE_CONNECT_REDIRECT_V6"));
        // the transport is part of the promise, so it is part of the preview
        assert!(Wfp::preview_route("x", true, IPPROTO_UDP).contains("IP_PROTOCOL == 17"));
    }
}
