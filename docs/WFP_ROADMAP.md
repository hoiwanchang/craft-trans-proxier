# WFP redirect route — status, what's done, and what you must install

Goal: per-connection redirect via the Windows Filtering Platform (WFP) so a
whitelisted program's traffic is proxied **without injecting a DLL into it**
(no message-hook, no per-process patching). This removes the driverless engine's
coverage gaps (services / console apps without a message pump / processes started
before install / cross-integrity).

## Honest status

| Path | State | Verified how |
|---|---|---|
| Driverless transparent hook (TCP) | ✅ done | live test `tests/transparent_windows.rs` + integration |
| Driverless transparent hook (connected UDP) | ✅ done | live test (UDP → SOCKS5 UDP ASSOCIATE → echo) |
| Driverless hook (unconnected + connected + **overlapped/IOCP** IPv6 UDP; `select`/`WSAEventSelect` readiness) | ✅ done | live tests in `tests/transparent_windows.rs` (event-completion, `GetQueuedCompletionStatus`, `select` round-trip) |
| App `:53` through the proxy with `dns_mode=proxy`, fail-closed when no chain can carry it | ✅ done | `rules::dns_*` (5) + live comparison of local-vs-proxy mode on the same resolver |
| Manual SOCKS5 / HTTP-CONNECT proxy engine | ✅ done | integration tests |
| WFP **control plane** (per-app connect-redirect filter, callout object, rollback) | 🟡 ABI **verified against the installed SDK headers**; **session handshake executed against the live BFE** (ignored test, un-elevated: `FwpmEngineOpen0` accepted, `FwpmSubLayerAdd0` correctly denied); filters themselves NOT installed | `src/wfp.rs`: GUIDs + `FWPM_FILTER0`/`FWPM_SUBLAYER0`/`FWPM_ACTION0`/`FWPM_SESSION0` sizes and offsets pinned by `wfp::tests::abi_*`; session is `FWPM_SESSION_FLAG_DYNAMIC` (installs die with the process) |
| WFP **data-plane DECISION logic** (per-connection redirect verdict) | ✅ done + unit-tested, agrees with `rules::decide` | `src/wfp_classify.rs` (`classify()`) |
| Callout identity + **per-flow original-destination record** (the kernel↔engine contract) | ✅ done + byte-pinned, serialised (no `transmute` across the boundary) | `wfp::REDIRECT_CALLOUT` (== `tpwfp::CALLOUT_KEY`), `wfp_classify::FlowRecord` (`to_bytes`/`from_bytes`, magic-checked) |
| `tpwfp` classify seam — sockaddr parse + safe PERMIT default + exports | 🟡 compiles (x64+i686), `remote_from_sockaddr` + `Classify` unit-tested; **redirect body NOT written or live-verified** | `tpwfp/` crate (`Classify`/`Notify`/`FlowDelete`) |
| WFP **engine-side ingress** for a callout (token-port pool + `(token, FlowRecord)` pipe → relay to the recorded original destination) | ✅ done + LIVE-tested with the test standing in for the driver | `src/wfp_ingress.rs`, `tests/wfp_ingress.rs`; off unless `TPROXIER_WFP_INGRESS=1` |
| Kernel callout **source** (`driver_wfp/tpdrv_wfp.c` + INF + build/install scripts) | 🟡 written, **never compiled or loaded** — deliberately C: the WDK's own `fwpsk.h` then type-checks every member instead of a hand-copied Rust layout silently corrupting memory at IRQL | `driver_wfp/`; `C_ASSERT` pins the 72-byte record against `wfp_classify::FlowRecord`; behaviour specified + host-tested in `wfp_callout_plan` |
| Control-device contract (service → driver: proxy pid + token pool + enable) | ✅ layout pinned on both sides | `wfp_ingress::{DriverConfig, IOCTL_TPDRV_*}` tests (140 bytes, `tokens` @12, CTL_CODE values) vs `tpdrv_wfp.h` + `install.ps1` |
| Kernel callout `.sys` binary + signing | ❌ needs the **WDK** to build and a test-signing host to load | `driver_wfp/build.ps1`, `install.ps1` |
| ~~User-mode callout DLL loaded by BFE~~ | ❌ **impossible, retired** | the BFE loads callouts from a kernel driver only; see below |

I deliberately did NOT install/enable WFP filters or any driver on your machine.
An unverified WFP filter could silently break your own networking. What CAN be
proven offline — the GUIDs and struct layouts — now is, against the SDK headers;
what cannot is the BFE's acceptance of a live filter, which needs elevation. Everything WFP here is **off by default** and gated behind an
explicit consent flag.

## Why the control-plane alone isn't enough

Two facts, both checked against the installed SDK headers
(`C:/Program Files (x86)/Windows Kits/10/Include/10.0.26100.0`):

* `FWPM_ACTION0` (shared/fwpmtypes.idl) is `{ FWP_ACTION_TYPE type; union { GUID
  filterType; GUID calloutKey; } }` — **20 bytes, with nowhere to put a redirect
  endpoint.** So a user-mode filter cannot redirect anything; it can only hand the
  flow to a callout (`FWP_ACTION_CALLOUT_TERMINATING = 0x5003`), which is exactly
  what `Wfp::route_app_to_callout` builds. An earlier draft of this file (and of
  `src/wfp.rs`) assumed a `FWPS_ACTION_REDIRECT` filter action with a `sockaddr`;
  that action does not exist in the user-mode ABI, and the layer GUID it used
  (`c56b2ac0-…`) is not `ALE_CONNECT_REDIRECT_V4` either — the real ones are
  `c6e63c8c-b784-4562-aa7d-0a67cfcaf9a3` (v4) and
  `587e54a7-8046-42ba-a0aa-b716250fc7fd` (v6), from `um/fwpmu.h`.
* `FWPS_CLASSIFY_OUT0` (shared/fwpstypes.idl) is `{ actionType, outContext,
  filterId, rights, flags, reserved }` — also no endpoint field. The redirect is
  emitted through the **layer-specific fixed output parameters** of the classify
  callback, whose types live in the WDK's `fwpsk.h`. That header is not installed
  here, which is the concrete reason the driver cannot be written "blind" in this
  workspace.

To redirect at all, the driver needs a WFP **callout** — and Microsoft documents
the whole proxy handshake, which supersedes the sketch that used to sit here (and
makes our token-port fallback unnecessary in the normal case). Steps, from
[Using Bind or Connect Redirection]:

1. `FwpsCalloutRegister1` (NOT `Register0`) — redirect layers require
   `classifyFn1` or later. Device object + `Classify`/`Notify`/`FlowDelete`,
   keyed by `trans_proxier::wfp::REDIRECT_CALLOUT`.
2. `FwpsRedirectHandleCreate0` once and cache the handle (every redirect uses it).
3. `FwpsQueryConnectionRedirectState0` first, **every** classify — this is what
   prevents an infinite redirect loop, and it is mandatory from Windows 8 on. If
   the flow was already redirected by us: do nothing. If the connect is to a local
   proxy: do not redirect it at all.
4. `FwpsAcquireClassifyHandle0`, then `FwpsAcquireWritableLayerDataPointer0` and
   cast `writableLayerData` to `FWPS_CONNECT_REQUEST0`.
5. In that structure: stash the ORIGINAL destination in `localRedirectContext`
   (+ `localRedirectContextSize`) — our contract puts a 72-byte
   `wfp_classify::FlowRecord` there — set `localRedirectTargetPID` to the proxy
   process pid (required for any loopback redirect to be valid), set
   `localRedirectHandle`, then rewrite `remoteAddressAndPort` to the engine's
   loopback endpoint.
6. `FwpsApplyModifiedLayerData0`, return `FWP_ACTION_PERMIT` from classifyFn
   (that is the sentence in "Types of Callouts" that reads like a filter-action
   instruction; a PERMIT-action filter cannot carry a `calloutKey`, so it can only
   describe the return), then `FwpsReleaseClassifyHandle0`.
7. **User-mode side — already implemented here.** On the accepted (redirected)
   socket the proxy queries the context and records with
   `WSAIoctl(SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT / _RECORDS)`; the engine
   reads the `FlowRecord` straight off the socket — see `wfp_ingress::query_redirect`
   and its use in `intercept::relay_server`. Opcodes from `shared/mstcpip.h:560-562`.
8. On the OUTBOUND (proxied) socket the proxy must
   `WSAIoctl(SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS, records)` so WFP relates the
   two connections — implemented as `wfp_ingress::apply_records`, called from
   `intercept::relay_established` when a redirect context was present.
9. Also register at `FWPS_LAYER_ALE_AUTH_CONNECT_V4/V6` and honour
   `FWPS_CONDITION_FLAG_IS_CONNECTION_REDIRECTED`,
   `FWPS_METADATA_FIELD_LOCAL_REDIRECT_TARGET_PID` and
   `FWPS_METADATA_FIELD_ORIGINAL_DESTINATION`, so our own proxy egress is never
   redirected again.
10. Teardown: `FwpsCalloutUnregisterById0`, `FwpsRedirectHandleDestroy0`; the
    filters/sublayer are removed with the dynamic BFE session when the app exits.

Redirection is supported for TCP, UDP, raw UDPv4 (no header-include option) and raw
ICMP — note `FwpsPendClassify0` is the pends-at-redirect-layer function, and UDP
datagram flows still need the datagram-layer handling that made games' UDP the hard
part in real products.

A callout **must be a kernel-mode driver** — `FwpsCalloutRegister1` lives in
`fwpkclnt.lib` and the Base Filtering Engine loads **only kernel callout drivers**,
never a user-mode DLL. (The `tpwfp` cdylib is therefore only the pure classify
*decision* logic, unit-testable in isolation; it is NOT a loadable callout and
cannot make the redirect work on its own.) So a real WFP redirect — recovering the
original destination per flow — **requires Option B (a signed kernel `.sys`)**.
There is no user-mode-callout path.

## What YOU must install to go further

### The only path to WFP redirect is a kernel callout driver (Option B below)
Because a WFP callout cannot be user-mode, there is no "no-signing" shortcut. The
`src/wfp.rs` control plane can open a BFE session and add filters (admin), but a
filter alone cannot recover the original destination — so it cannot implement a
correct redirect without the callout `.sys`. Until the driver exists, the
**driverless hook (`intercept::Engine`) remains the working, verified solution.**

### Option B — kernel WFP callout driver (required for WFP redirect)
- **Windows Driver Kit (WDK)** matching your Windows build.
- Rust kernel crates: `wdk` / `wdk-sys` (build with the WDK's `cmake`/`msbuild` or
  the `eWDK`), target `x86_64-pc-windows-msvc`, link `netio.lib fwpkclnt.lib`.
- **Driver signing**:
  - Dev/test: `bcdedit /set testsigning on` then reboot, sign with a self-made cert
    added to the Local Machine Trusted Root + Trusted Publisher stores.
  - Production (Win10+): an **EV code-signing certificate** + Microsoft
    **Partner Center attestation signing** (WHQL optional) to load without
    test-signing mode. Kernel drivers are blocked unless WHQL/attestation-signed.
- Install as a service: `sc create tpdrvfwpsvc type=kernel binPath=...` then
  `sc start`, or `pnputil`. Uninstall: `sc stop` + `sc delete` + `pnputil /delete-driver`.

## Safe operation + ROLLBACK

- Always back up before touching WFP:
  `netsh wfp show state file=wfp-backup.xml`
- Our filters live in a dedicated sublayer (`src/wfp.rs::REDIRECT_SUBLAYER`), so
  rollback = delete that sublayer, or nuke WFP custom policy:
  `netsh wfp reset filters`  (also clears your other custom filters — know before running).
- The engine mutex `tproxierPE` means only one transparent engine runs at a time.

## Recommended sequence for you
1. Use the **driverless** engine now (works for TCP + connected-UDP whitelisted
   apps; verified). This needs no driver/signing — just run elevated.
2. WFP redirect (recovering the original destination for arbitrary processes,
   incl. services/no-pump/UDP) **requires a kernel callout driver** — there is no
   user-mode callout. It needs the WDK, driver signing (test-signing for dev, EV +
   Microsoft attestation for production), and an isolated VM to build/load safely.
   That driver is NOT buildable or verifiable in this workspace; it is a separate,
   user-side deliverable. The decision logic it must call is already here and
   unit-tested (`wfp_classify::classify`), as is the user-mode filter scaffolding
   (`src/wfp.rs`).

## Reference implementation this driver was checked against

`network/trans/WFPSampler/sys/ClassifyFunctions_ProxyCallouts.cpp` in
[microsoft/Windows-driver-samples](https://github.com/microsoft/Windows-driver-samples) —
Microsoft's own redirect callout. Comparing against real code (not just prose) caught
three more things in `tpdrv_wfp.c`:

1. The redirect work must be guarded by `classifyOut->rights & FWPS_RIGHT_ACTION_WRITE`;
   an earlier callout may have taken the right to change the action away.
2. Acquiring the writable layer data CLEARS that right, so **every path that changes
   nothing must give it back** (`rights |= FWPS_RIGHT_ACTION_WRITE`). A path that really
   did redirect leaves it cleared — that is how the callout marks the decision as final.
3. Missing `REDIRECT_RECORD_HANDLE` metadata means "not redirected", i.e. continue; my
   first version bailed out, which would have silently disabled the route rather than
   failing loudly.
   It also confirms the fixes already made: `FwpsQueryConnectionRedirectState(
   metadata->redirectRecords, handle, &context)` returns the state, `layerId` is compared
   against `FWPS_LAYER_ALE_CONNECT_REDIRECT_V4/V6`, and the context handed to
   `localRedirectContext` is opaque driver data of a stated size — exactly what
   `FlowRecord` is, though the sampler stores `SOCKADDR_STORAGE * 2` where we store a
   fixed 72-byte record so the service can parse it without the kernel headers.

## Verification ledger for the driver source

What has been checked, and how, since none of it has been executed:

| Item | How it was verified | Still open |
|---|---|---|
| `FWPM_*` / `FWP_*` struct sizes, offsets, enum values used by `src/wfp.rs` | transcribed from the installed SDK IDL, asserted in `wfp::tests::abi_*`, **and re-derived by gcc against MinGW's own copies of the same headers** (`driver_wfp/abi_check.c`, fails to build on drift) | — |
| `FWPS_CONNECT_REQUEST0` member names the driver writes | quoted verbatim from the DDI structure page | the WDK compile is the final word |
| `FwpsAcquireWritableLayerDataPointer0`, `FwpsApplyModifiedLayerData0`, `FwpsAcquireClassifyHandle0`, `FwpsQueryConnectionRedirectState0`, `FwpsRedirectHandleCreate0`, `FwpsCalloutRegister1` prototypes | read off each function's DDI page (2026-11-25) and listed in the header comment of `tpdrv_wfp.c` | same |
| the 72-byte record, byte for byte, between the two implementations | a shared golden buffer, asserted identically by `wfp_classify::record_matches_the_shared_golden_bytes` and `driver_wfp/test_record.c` (memcmp) — the check that caught defect 5 below | — |
| the redirect decision and every byte it writes (sockaddr v4/v6 layout, network-order port, 72-byte context) | implemented + unit-tested in `trans_proxier::wfp_callout_plan`, and the **C that will actually run is compiled and executed on a host** too: `driver_wfp/record.c` + `test_record.c` (70 checks, gcc 16.2) assert the same literals as the Rust tests | — |
| the driver's call sequence and argument shapes | `FWPS_CALLOUT_CLASSIFY_FN1` (7 params incl. classifyContext and `FWPS_FILTER1`) and `FwpsCalloutRegister1(void*, const FWPS_CALLOUT1*, UINT32*)` quoted from their DDI pages and matching our callbacks; six defects found this way and fixed (see below) | same |
| the kernel TU's **internal consistency** — identifiers exist, argument counts and kinds match, nothing is read before it is written, the callout struct holds functions of the right shape | `build.ps1 -Test` type-checks `tpdrv_wfp.c` + `record.c` with `gcc -Wall -Wextra -Werror=incompatible-pointer-types` against `driver_wfp/wdk_shim.h` (the `fwpsk.h` declarations, transcribed from the DDI pages) and MinGW-w64's copy of Microsoft's own `ddk/ntddk.h`. Six further defects found and fixed (second list below). The check was **proved able to fail**: an argument removed from `FwpsCalloutRegister1` and the old `notifyFn` signature each stop it | struct **layout**: the shim omits members deliberately, so only a WDK compile is authoritative |
| deployment order | the engine treats `FWP_ACTION_CALLOUT_TERMINATING` filters as **BLOCK** until the callout registers — which is why the control plane's filters carry `FWPM_FILTER_FLAG_PERMIT_IF_CALLOUT_UNREGISTERED`, and why `wfp --apply` refuses when the driver is absent | — |
| where the encoders end and kernel-only code begins | `record.c` includes no kernel headers at all, so the byte-level half is toolchain-independent and host-tested; only the acquire/apply sequence in `tpdrv_wfp.c` needs a WDK compiler | the WDK compile |
| the service half (token listeners, context read-back, records set on the egress socket, per-app filters, rollback) | compiled + tested here, including a live `FwpmEngineOpen0` handshake (`--ignored` test) | filter installation needs elevation |
| the filter struct handed to `FwpmFilterAdd0` | observed on this host: the call returned **0x5 E_ACCESSDENIED**, not E_INVALIDARG — the BFE parsed our `FWPM_FILTER0` (built from the mirror pinned above) far enough to make a permission decision | the accepted-and-installed case still needs an elevated run |

Six defects were found by that reading and are already fixed in `tpdrv_wfp.c`. They are
worth recording because **none of them would have produced a useful symptom** — this is
what a first WDK build would otherwise have had to discover by debugging a network stack:

1. `FwpsAcquireWritableLayerDataPointer0`'s second parameter is the **filter id**
   (`Filter->filterId`), not the redirect handle. Both are pointer-sized, so the C
   compiler would very likely have stayed silent; the redirect would simply not have
   worked, at best.
2. `FwpsQueryConnectionRedirectState0` **returns** an
   `FWPS_CONNECTION_REDIRECT_STATE` and its first parameter is the
   **redirect-records handle from the ALE metadata**. Treating it as
   `NTSTATUS …(classifyHandle, handle, &state)` plus a bitmask test would have made
   the anti-loop check never fire — an infinite redirect loop, not a warning.
3. The flow-delete callback takes **three scalars**
   (`UINT16 layerId, UINT32 calloutId, UINT64 flowContext`) — there is no
   `FWPS_FLOW_DELETE_ARGUMENT` parameter. The earlier version would not have compiled,
   which is the *good* outcome; it is listed here because it was written from memory.
4. `FwpsFlowAssociateContext0` takes `(flowHandle, layerId, calloutId, flowContext)` —
   not the classify handle first, and the context must be non-zero and needs a
   `flowDeleteFn` registered (we register one, which is what makes the UDP token pool
   recoverable).
5. **A port-endianness bug in the shared record itself**, found only by comparing the C
   and Rust encodings byte for byte: `FlowRecord` serialised `port_be` with
   `to_be_bytes()`, which double-swaps it (the field already holds `host.to_be()`), so
   every WFP-redirected flow would have dialled **port 47873 instead of 443**. The
   Rust round-trip test could never see this — it agreed with itself. Fixed to write
   the wire octets, matching `sin_port` exactly as the driver does.
6. `processId`, `flowHandle` and `redirectRecords` were read unconditionally. Those
   metadata fields are only valid when the engine flags them present, so each read now
   sits behind `FWPS_IS_METADATA_FIELD_PRESENT`; without that guard the driver would
   attribute flows to garbage pids instead of failing.

### Found by the compiler pass (same day)

`fwpsk.h` is still absent, but MinGW-w64 ships Microsoft's own `ddk/ntddk.h`, and
`wdk_shim.h` carries the `fwpsk.h` half transcribed from the DDI pages. That let an
ordinary compiler read the kernel file for the first time — the first thing it had ever
read it. Six more defects fell out:

1. **The UDP path used its record before producing it.** `TpdrvClassify` did
   `*record = udpRecord` and called `TpdrvUdpReserve(…, &udpRecord)` *afterwards*, so
   every redirected datagram carried an uninitialised destination — a driver that loads,
   "works", and proxies to nowhere.
2. **The exhausted-table path leaked.** It returned after `ExAllocatePool2` without
   freeing the record and without releasing the token: 72 nonpaged bytes plus one UDP
   token per refused flow, until UDP redirection stopped entirely.
3. **`DriverEntry` called `TpdrvApplyConfig(0, 0, NULL, 0)`** — four arguments to a
   six-parameter function. A hard compile error, i.e. the first WDK build would have died
   here and revealed nothing else.
4. **The loopback bail-out restored `actionType` but not `FWPS_RIGHT_ACTION_WRITE`.**
   After the acquire the engine has cleared that right; withholding it stops every *other*
   vendor's callout acting on the flow. All four "change nothing" exits now share one
   `TpdrvPermitUnchanged` helper, because a fourth copy of the four statements is a fourth
   chance to omit one.
5. **`notifyFn` had the wrong shape.** It was `(UINT32, const FWPS_FILTER1*, uint64_t) -> VOID`;
   `FWPS_CALLOUT_NOTIFY_FN1` is `(FWPS_CALLOUT_NOTIFY_TYPE, const GUID*, FWPS_FILTER1*) -> NTSTATUS`.
   C takes that as at most a warning, and the filter engine then hands a `GUID*` to code
   dereferencing a filter pointer at `DISPATCH_LEVEL`. Hence `-Werror=incompatible-pointer-types`
   in the check, and the red test that restores the old signature to prove it bites.
6. **Token selection happened before the decisions that permit the flow.** Reordering the
   loopback / anti-loop checks ahead of `TpdrvTakeToken` means permitted flows no longer
   consume pool slots.

Reading the same pages for the transcription also settled two things the code now states
explicitly: `localRedirectContext` is **owned by WFP from Windows 8 and freed when the
proxied flow is deleted** (so `TpdrvFlowDelete` must *not* free it — doing so is a pool
double-free, not a leak), and the documented anti-loop recipe has a second half: a
`previousVersion` whose `localRedirectHandle` is not ours means another product already
redirected this flow locally, and stacking ours on top is how two proxies deadlock.
Microsoft's snippet applies there with `FWPS_CLASSIFY_FLAG_REAUTHORIZE_IF_MODIFIED_BY_OTHERS`;
we apply with `0`, because we change nothing and must not ask for reauthorization.

Related trap now documented in the code: `FwpsAcquireWritableLayerDataPointer0` sets
`classifyOut->actionType = FWP_ACTION_BLOCK` **and clears `FWPS_RIGHT_ACTION_WRITE`** on
success, so every exit path after a successful acquire must restore the action *and* give
the right back — dropping the connection is the first symptom, starving every other
vendor's callout is the second, and the loopback refusal had the second bug until the
compiler pass (`TpdrvPermitUnchanged` now covers all four exits).

## The supervisor's two silent-failure guards

`trans-proxier wfp --apply` is the long-lived half of the route, and it now closes the
two ways a WFP redirect fails *quietly*:

* **Drift.** `wfp_ingress::ensure_armed()` polls `IOCTL_TPDRV_GET_STATUS` every 2 s and
  re-pushes the pool whenever the driver's answer disagrees with this process on
  `enabled`, `proxy_pid`, `token_count` or `udp_token_count`. The case that matters is a
  driver restart: `DriverEntry` deliberately configures nothing until the service pushes,
  so a reloaded driver leaves every filtered connect permitted — indistinguishable from a
  rule that simply does not match, with filters still visible in `netsh wfp show state`.
  The predicate is pure (`needs_reconfigure`) and unit-tested in all directions, including
  that "want disabled" is itself a change that must be pushed, and that both sides
  truncate the pool at 64 so a large pool cannot re-push every poll.
* **Exit.** The token ports are sockets in *this* process. An armed driver outliving us
  would redirect the next whitelisted connect into a closed port, so `--once` disarms
  before returning, and a console-control handler flags Ctrl+C so the loop can call
  `configure_driver(false)` and *then* exit — the IOCTL cannot be issued from inside the
  handler itself, which runs on a system thread while the process is already dying.

Neither is provable on this host: both need a loaded driver to talk to. What is proven
here is the decision logic (the unit tests) and that the read-only `wfp --verify` path
still never reconfigures what it is describing.

## Two things a driver author must not be surprised by

**1. This host has no WDK — verified, not assumed.** `Windows Kits/10/Include` contains
only `shared/um/ucrt/winrt/cppwinrt` (no `km`), `Lib/10.0.26100.0` has only `ucrt` and
`um`, there is no EWDK root, and `rustup toolchain list` shows stable only. ~~`tpdrv_wfp.c` cannot be **built** here at all~~ — that turned out to be wrong in a
useful way. The WDK's `km` headers and kernel import libraries are distributable as the
`Microsoft.Windows.WDK.x64` NuGet package (a zip; no installer, nothing registered), and
MSVC is already on this box, so **`driver_wfp/build_cl.ps1` compiles and links
`tpdrv_wfp.sys`** — x64, subsystem Native, all ten `Fwps*` DDIs importing from
`fwpkclnt.sys`. That build forced four signature corrections; the table is in
`driver_wfp/README.md`. What is *still* not available here is everything after the build:
code signing, `bcdedit /set testsigning on`, and a host to load the driver on.

Before that, `build.ps1 -Test`'s gcc type-check (against `wdk_shim.h` + MinGW's copy of
Microsoft's `ddk/ntddk.h`) was the only compiler this file had ever met — and it remains
the check that runs on a machine with none of the above. Any claim that the driver
"builds" must come from a machine that actually has the WDK.

**2. UDP takes a token per flow — implemented on both sides.**
The redirect layers do cover UDP (Microsoft lists TCP, UDP, header-less raw UDPv4 and raw
ICMP as redirectable), but a connected UDP socket only accepts replies from the port it was
redirected to, so one shared listener cannot serve several apps. Hence two pools:
`wfp_ingress::token_ports()` (TCP, shareable because each accepted socket carries its own
redirect context) and `wfp_ingress::udp_token_ports()` (one socket per concurrent flow).
`TpdrvTakeToken(IsUdp)` selects between them, and `TpdrvClassify` reads the protocol from
the incoming values *before* taking a token, since the pool choice depends on it. A UDP
datagram arriving on a token is prefixed with a synthesised `Req` header
(`intercept::req_from_flow`), so it rides the same already-verified relay as the hooked
path rather than a second data path only a driver could exercise.
Live test: `tests/transparent_windows.rs` (stage → send → echo through SOCKS5 UDP
ASSOCIATE). Host C gate: the TCP and UDP pools never hand out each other's ports.

Both halves are now written: `TpdrvClassify` reserves a token and associates the token with
the flow (`FwpsFlowAssociateContext0`), `TpdrvFlowDelete` releases it via that context, the
service asks `IOCTL_TPDRV_QUERY_FLOW` when a datagram arrives (a datagram has no accepted
socket to query, unlike TCP), and the table itself — reserve / look up / release / exhaust /
reuse — is compiled and exercised on the host because it lives in `record.c`, which includes
no kernel headers. What remains genuinely unknown is only what a compiler with `fwpsk.h`
would check: the kernel member names and prototypes used in `tpdrv_wfp.c`.

Note also that the WDK's own proxy-callout sample comments that Microsoft *recommends*
STREAM-layer proxying over redirecting to a local service. Connect-redirect is still the
right layer for per-app proxying (it is what a Proxifier-class product needs), but that
recommendation is why UDP is the hard part in real products, not an afterthought.

## What is left to make the WFP route operable end-to-end

In order, with what each one needs:

1. **Compile the driver** — open `driver_wfp/tpdrv_wfp.sln` in Visual Studio with the
   WDK extension (settings copied from Microsoft's own WFP driver project), or run
   `driver_wfp/build.ps1` from an EWDK prompt. Since 2026-11-25 this is no longer the
   *first* compiler to read the file: `build.ps1 -Test` type-checks both kernel
   translation units with gcc against `wdk_shim.h` + MinGW's `ddk/ntddk.h`, which took
   out six defects (above). What a WDK build can still report is therefore narrow —
   struct **layout** (member offsets the shim deliberately omits), the include set
   (`UFIELD_OFFSET`, `ExAllocatePool2`, `KeAcquireSpinLockRaiseToDpc` reachability) and
   linking against `FwpKClnt.lib`. Treat anything beyond that as information about the
   transcription, not as a surprise.
2. **Sign + load in a VM** — `bcdedit /set testsigning on`, the certificate in
   LocalMachine\Trusted Root + Trusted Publishers, then
   `install.ps1 -IDeclareIAmInAVM` (`-Uninstall` reverses it).
3. ~~One user-mode command path~~ **done**: `trans-proxier wfp` previews the exact
   filters (both families, real GUIDs) and `wfp --apply
   --i-consent-to-install-wfp-filters` arms the route — it starts the engine's token
   listeners, pushes the token pool + pid to the driver, registers the callout object
   and installs the filters, then keeps running (exit withdraws everything through the
   dynamic session; `--once` for a scripted probe). It refuses to install anything when
   the driver is absent, because inert filters would be worse than none. Verified
   end-to-end on a machine with no driver: dry run ✅, missing consent ✅ refused,
   missing driver ✅ refused, nothing touched.
4. **Verify on the host** — `trans-proxier wfp --verify` is the acceptance gate: it
   reports the driver's presence from its control device (read-only, no reconfiguration),
   the bound token pools, whether the per-app filters were accepted (installation still
   needs the consent flag *and* elevation), and — decisively — whether a probe connect to
   the unroutable `198.51.100.99:80` was actually redirected with its ORIGINAL destination
   recovered — and that the flow was credited to **this process**, which is the whole
   point of the kernel route (a tunnel alone could have come from the ws2_32 hook).
   It exits non-zero until every row passes, so it is usable as a CI/manual gate.
5. **Arm it from the long-lived process** — done in code: `src/wfp_route.rs` is the
   `prepare()` → `Engine::start()` → `commit()` sequence the GUI runs when 启用 WFP 内核重定向
   is ticked, and its `Route` guard disarms the driver and withdraws the filters on drop
   (stop button, untick, or exit). Two phases because the engine binds the token ports
   only if the ingress path is already latched, and the driver must not be handed a pool
   that does not exist yet. The refusal rules (no consent / no driver / empty whitelist /
   no bound TCP *or* UDP listeners) are pure and unit-tested; the FFI side needs the
   loaded driver, and reports rather than assumes.
   Cross-check with `netsh wfp show state`: it should list the callout
   `d7a1f002-2222-4333-9999-999999999999` and **four redirect filters per whitelisted
   app** (v4/v6 × TCP/UDP — the transport is tested by the filter, not only by the
   callback); then a proxied app's connection should be tunnelled with the original
   destination arriving through `SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT`.
   (this sketch is superseded in detail by the runbook at the end of this file: the
   acceptance gate now runs as one self-contained consented `wfp --verify`, with no
   supervising `--apply` alongside it - that process would hold the driver claim)

Rollback is cheap by construction: the service's BFE session is
`FWPM_SESSION_FLAG_DYNAMIC`, so stopping trans-proxier removes its sublayer, callout
object and filters without `netsh wfp reset filters` (which also wipes unrelated
custom filters — last resort).

## Current cleanup note
`target/debug/tpdrv.dll` is still file-locked by ~35 apps that the earlier global-
hook test injected; the *fixed* build is validated under `target_check/`. Close
those apps (or reboot) then `cargo build --workspace` to land it in `target/debug`.

---

## VM acceptance run (the only step left)

Items (2) connected+overlapped IPv6 UDP and (3) the app's `:53` through the proxy are
done and live-proven on x64 and i686. This file's remaining subject is item (1): the
kernel redirect. Everything that can be measured without loading a driver is measured
(185 host-run C checks incl. the executed classify path, ABI pinned against the real
SDK headers, image Authenticode-signed). What is NOT proven anywhere in this repo is
that a loaded callout actually rewrites a connect and returns the original
destination. That needs one elevated run in a test-signing VM.

1. `bcdedit /set testsigning on` then reboot (VM only - this changes the machine).
2. Import `driver_wfp/out/tpdrv_test.cer` into `LocalMachine\Root` AND
   `LocalMachine\TrustedPublisher`. The private key never leaves the VM that built it;
   nothing about it lives in this repository.
3. `driver_wfp/vm_check.ps1 -IDeclareIAmInAVM -SkipBuild -App <path to trans-proxier.exe>`
   from an elevated prompt. It runs ONE self-contained consented `wfp --verify`: that
   process binds its own token listeners, hands the driver its own pool, installs
   per-transport filters for its own image, probes TEST-NET-3 (198.51.100.99:80, which
   is unroutable by design), and withdraws everything on exit. It deliberately does NOT
   run alongside a supervising `--apply`, because the driver takes configuration only
   from the process holding the claim.
4. Roll back: `driver_wfp/vm_check.ps1 -IDeclareIAmInAVM -Teardown`.

Reading a failed row:

| Row | Meaning |
|---|---|
| `callout driver present` + `callouts_registered=0` or `redirect_handle_valid=0` | the
  .sys loaded but `DriverEntry` failed part-way. Filters still install and, with
  permit-if-callout-unregistered, traffic goes DIRECT - nothing is proxied. |
| `tpdrv_wfp.sys is not loaded (or it refused/short-answered the status IOCTL` | either
  genuinely absent, or an older .sys returned fewer than 32 status bytes. The service
  refuses a short reply rather than reading the unwritten tail as zeros. |
| `claim held by pid N` | another process owns the driver's configuration; restart the
  TpDrvWfp service (or stop that route) before re-running the gate. |
| `N UDP flow(s) were permitted untouched` | the engine indicated no flow handle for
  those datagrams, so the token could never be returned; refusing was the safe choice
  but that app's UDP is going direct. |
| redirect row FAIL while the rows above pass | the callout ran but did not modify the
  connect, or the redirect context did not come back through
  `SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT`. |
