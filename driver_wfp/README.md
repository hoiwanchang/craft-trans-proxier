# `driver_wfp` — the WFP callout driver source

## Why C, when everything else here is Rust

A WFP redirect callout has to touch `FWPS_CONNECT_REQUEST0`,
`FWPS_INCOMING_VALUES0`, `FWPS_INCOMING_METADATA_VALUES0` and `FWPS_CALLOUT1`. Those
are defined in the WDK's `fwpsk.h`, which is **not** part of the Windows SDK — and the
machine this project was developed on has only the SDK. A Rust driver would therefore
have to redeclare those structures by hand, and a wrong field there does not fail to
compile: it corrupts memory at IRQL and takes the host's networking with it.

Writing the callout in C moves that risk into the compiler. If a member name or a
prototype is wrong, `cl.exe` says so during the build, in a VM, before the driver ever
runs.

## What the driver does

1. `DriverEntry` creates `\Device\TpDrvWfp` (+ `\DosDevices\TpDrvWfp`), creates and
   caches a redirect handle with `FwpsRedirectHandleCreate0`, and registers its
   callbacks with **`FwpsCalloutRegister1`** — the redirect layers are not served by
   `classifyFn0`.
2. The service pushes its pid, the token-port pool and an enable flag through
   `IOCTL_TPDRV_SET_CONFIG`. Until that happens the driver is loaded and inert, which
   is the safe default.
3. `TpdrvClassify` runs per filtered connect:
   - asks `FwpsQueryConnectionRedirectState0` with the **redirect-records handle from
     the ALE metadata** and returns PERMIT unchanged if we already redirected this
     flow (the anti-infinite-loop requirement; and the call *returns* the state, it is
     not an NTSTATUS-with-out-parameter call);
   - takes a token port (round-robin, lock-free: two flows may share one, because each
     accepted socket carries its own context);
   - `FwpsAcquireClassifyHandle0` → `FwpsAcquireWritableLayerDataPointer0` (second
     argument is **`Filter->filterId`**) → stores the original 4-tuple in a freshly
     allocated `TP_FLOW_RECORD`, sets `localRedirectTargetPID`, `localRedirectHandle`,
     `localRedirectContext`/`…Size`, rewrites `remoteAddressAndPort` to loopback in the
     **same address family** as the original destination, then
     `FwpsApplyModifiedLayerData0`;
   - restores `classifyOut->actionType = FWP_ACTION_PERMIT` on **every** path after a
     successful acquire — the acquire itself forces `FWP_ACTION_BLOCK`, so a missing
     restore silently drops the connection.
4. UDP is served from its own pool (`udp_token_ports`, one socket per flow) because a
   connected datagram socket only accepts replies from the port it was redirected to. Two
   rules follow from that, and both are now enforced in `record.c` rather than assumed:
   * **One flow per distinct token port.** The service resolves a redirected datagram's
     destination *by token*, so double-booking a port does not share load — it makes the
     second flow's traffic undeliverable. `TpdrvUdpReserve` therefore scans the live table
     and **refuses** when every configured port is taken: capacity is the port pool (16 as
     the service binds it), *not* `TPDRV_MAX_TOKENS` (64). A refusal leaves the flow
     untouched, so it fails as "not proxied" rather than as "network broken".
   * **The token comes back.** `FwpsFlowAssociateContext0` is called *before* the redirect
     is committed, and if it fails the reservation is released and the layer data is
     applied unchanged — because `flowDeleteFn` only runs for flows that carry a context,
     so ignoring that return value would leak a slot for the life of the driver.
     (`test_classify.c` case 11 asserts both halves, including that the active-flow count
     does not move.)
5. The service accepts on that token port and reads the record back with
   `SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT`, then sets
   `SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS` on its outbound socket. That half is
   already implemented and live-tested in `../src/wfp_ingress.rs`.

There is deliberately **no** per-flow policy in the kernel: whitelisting is expressed
as filters (`../src/wfp.rs`), so this callback only runs for programs the user chose.
No user-mode round trip, no lock, no pageable memory at DISPATCH_LEVEL.

The decision and the byte layouts it produces are specified and tested in Rust —
`trans_proxier::wfp_callout_plan` (sockaddr encodings, anti-loop precedence, token
exhaustion) and `trans_proxier::wfp_classify::FlowRecord` (the 72-byte context). This
file mirrors them; if the two disagree, the Rust tests are the reference.

## Checking what can be checked without the WDK

The driver is split so that the risky half does not need a WDK to be tested:
`record.c` holds the byte-level output (sockaddr encodings, the 72-byte context, the
token pool) and includes no kernel headers at all.

```
# encoders, compiled and executed with an ordinary compiler
gcc -I. record.c test_record.c -lws2_32 -o test_record && ./test_record     # 70 checks
gcc abi_check.c -o abi_check && ./abi_check                                 # ABI cross-check
# both spellings of the pool allocation are compiled: modern + pre-2004 WDK fallback
```

Both run from this directory, and `build.ps1 -Test` runs them — plus the kernel
type-check below — for you. Last run here (gcc 16.2): 41 encoder checks ✅ byte-for-byte
against the Rust spec (including that TCP and UDP tokens never come from each other's
pool), the ABI cross-check ✅, and both kernel translation units type-check clean ✅.

`abi_check.c` asks a C compiler what the real WFP headers say about every struct and
enum `src/wfp.rs` mirrors, and refuses to build on drift — a hand-written test can only
agree with itself, so this is the independent check. Run here with gcc 16.2 against
MinGW-w64's copies of `fwptypes.h`/`fwpmtypes.h`/`fwpmu.h`: every size, offset, action
and data-type value agreed with the Rust mirror.

## Type-checking `tpdrv_wfp.c` without the WDK

`fwpsk.h` is the one thing this machine does not have, so until now the kernel file had
never been near a compiler — while being exactly the file whose mistakes are invisible
until they are expensive. It turns out most of those mistakes do not need the WDK to
find, only *some* declaration to check against:

```
gcc -fsyntax-only -Wall -Wextra -Werror=incompatible-pointer-types \
    -DTPDRV_SYNTAX_CHECK -include wdk_shim.h -I. -I<gcc-root>/x86_64-w64-mingw32/include/ddk \
    tpdrv_wfp.c record.c
```

Two sources of truth, deliberately mixed:

* **`<ntddk.h>` is MinGW-w64's copy of Microsoft's own kernel header**, so `DRIVER_OBJECT`,
  `DEVICE_OBJECT`, `IRP`, `IO_STACK_LOCATION`, `UNICODE_STRING`, `NTSTATUS` and the
  `Io*`/`Ke*`/`Ex*` prototypes behind the device half are the genuine declarations, not my
  transcription. (It cannot be combined with user-mode `winsock2.h` — `ntddk.h` defines
  `_NTDDK_`, after which MinGW's `minwinbase.h` no longer compiles. Hence the second bullet.)
* **`wdk_shim.h` transcribes the `fwpsk.h` half** from the Microsoft DDI pages, plus the
  five `sockaddr` structs. It declares only the members this driver touches and omits the
  ones in between, so **its offsets are not the WDK's** — that is the honest limit. The
  driver is therefore written to reach every kernel struct *by name and never by offset*,
  which is what makes the check meaningful: a wrong member name cannot compile on either
  side, and a wrong offset is impossible by construction. Layout still belongs to the real
  headers, as the first section of this README says.

### The six things it caught, all on the first run

None of these are theoretical — each was in the file:

1. **The UDP path read its record before producing it.** `TpdrvClassify` did
   `*record = udpRecord` and only *called* `TpdrvUdpReserve(…, &udpRecord)` afterwards, so
   every redirected datagram would have carried an uninitialised destination.
2. **…and leaked on the way out.** The exhausted-table branch returned after
   `ExAllocatePool2`, without freeing the record or releasing the token: 72 nonpaged bytes
   plus a UDP token per refused flow, until UDP stopped working.
3. **`TpdrvApplyConfig(0, 0, NULL, 0)` in `DriverEntry`** — four arguments to a
   six-parameter function. A plain compile error, i.e. the first WDK build would have died
   here before revealing anything interesting.
4. **The loopback branch never gave back `FWPS_RIGHT_ACTION_WRITE`.** After
   `FwpsAcquireWritableLayerDataPointer0` the engine has cleared that right and forced
   `FWP_ACTION_BLOCK`; a path that "changes nothing" must restore both, or every *other*
   vendor's callout stops seeing the flow. All four bail-outs now go through one
   `TpdrvPermitUnchanged` helper so a fifth path cannot forget it.
5. **`notifyFn` had the wrong shape entirely.** It was
   `(UINT32, const FWPS_FILTER1*, uint64_t) -> VOID`; the documented
   `FWPS_CALLOUT_NOTIFY_FN1` is `(FWPS_CALLOUT_NOTIFY_TYPE, const GUID*, FWPS_FILTER1*) -> NTSTATUS`.
   C takes that mismatch as at most a warning, and then the filter engine hands a `GUID*`
   to code dereferencing it as a filter at `DISPATCH_LEVEL`. This is why the command above
   carries `-Werror=incompatible-pointer-types` — and why the flag was verified to bite:
   restoring the old signature makes the check report exactly one error.
6. **`build.ps1 -Test` could not run on a machine without the WDK** — the `cl.exe` guard
   ran first and threw, so the documented command failed on the very machine it was written
   for. The checks now run before the toolchain is needed, and `-Test` alone exits with a
   note that nothing was built.

Reading the DDI pages for the check also surfaced a *design* gap rather than a bug: the
documented anti-loop recipe has a second half. `FwpsQueryConnectionRedirectState0` answers
for **our** redirect handle, and separately the connect request carries a
`previousVersion` chain; if an earlier redirect there has a `localRedirectHandle` that is
not ours, a second local redirect would stack two proxy products on one flow. The
classify path now checks that too (Microsoft's snippet applies with
`FWPS_CLASSIFY_FLAG_REAUTHORIZE_IF_MODIFIED_BY_OTHERS`; we apply with `0` because we change
nothing and so must not ask for reauthorization).

The same pages settled the record's lifetime, which is easy to get expensively wrong:
`FWPS_CONNECT_REQUEST0.localRedirectContext` is **owned by WFP from Windows 8 on and freed
when the proxied flow is deleted** — so `TpdrvFlowDelete` must not free it, and the code
says so where a future reader might be tempted to "fix" the non-existent leak.

Both red tests were run through the same gcc with the same flags:

```
# drop an argument from FwpsCalloutRegister1  → "too few arguments"
# restore the old (UINT32, FWPS_FILTER1*, uint64_t) notifyFn → 1 error, exit 1
```

## Assumptions the build will confirm

- `ExAllocatePool2(POOL_FLAG_NON_PAGED, …)` needs a **2004-or-later WDK to build** against.
  `TPDRV_ALLOC` in `tpdrv_wfp.c` falls back to `ExAllocatePoolWithTag(NonPagedPoolNx, …)`
  when the flag is absent, and `build.ps1 -Test` compiles **both** spellings
  (`-DTPDRV_TEST_LEGACY_POOL`) so neither branch is shipped unread. Run-time is still
  Windows 10 2004+ for the `ExAllocatePool2` path only if you keep it; the fallback works
  against older pools. Note that freeing is *not* our job either way: WFP owns
  `localRedirectContext` from Windows 8 on.
- Address families and `sockaddr` spellings follow the WDK typedefs (`SOCKADDR_IN`,
  `PSOCKADDR_IN6`, `IN_ADDR.S_un.S_addr`) rather than Winsock's `struct` tags, since
  the kernel headers do not provide the latter; `record.c` builds against both because
  MinGW defines the same typedefs, which is how it stays host-testable.
- `notifyFn`/`classifyFn`/`flowDeleteFn` signatures match `FWPS_CALLOUT1` exactly (the
  flow-delete callback is three scalars: layerId, calloutId, flowContext).

## Opening it in Visual Studio

`tpdrv_wfp.sln` / `tpdrv_wfp.vcxproj` are provided so the normal WDK workflow works:
open the solution, pick `Debug|x64`, Build. Its settings (`PlatformToolset
WindowsKernelModeDriver10.0`, `ConfigurationType Driver`, `DriverType WDM`,
`TargetVersion Windows10`, `$(DDK_LIB_PATH)\FwpKClnt.lib` + ntoskrnl/NDIS) were taken
from Microsoft's own WFP driver project — `network/trans/WFPSampler/sys/
WFPSamplerCalloutDriver.vcxproj` in microsoft/Windows-driver-samples — simplified to
plain WDM without WPP tracing or a resource file.

Two deliberate choices worth knowing about:

* `test_record.c` and `abi_check.c` are **not** compile units of the driver (verified:
  the project compiles exactly `tpdrv_wfp.c` + `record.c`). They are host tests and must
  never be linked into a kernel image.
* `TreatWarningAsError` is **false**, unlike the Microsoft sample. Code written without a
  compiler in reach deserves a warning list on the first build, not a red X. Turn it on
  once the build is clean.

## Who is allowed to arm the redirect

The control device is opened by name, and `\Device\TpDrvWfp` is not restricted to the
proxy service — so an early version of this driver let **any local process** push
`IOCTL_TPDRV_SET_CONFIG` with its own pid and token ports, which is to say: point every
whitelisted application's traffic at itself. A driver that "works" would have been a
redirector for whoever asked loudest.

The rule now lives in `TpdrvConfigMayBeSetBy` / `TpdrvMayQueryFlow` (pure, and the truth
table runs in `test_record.c`):

| Situation | SET_CONFIG | QUERY_FLOW |
|---|---|---|
| driver unclaimed (owner pid 0) | first caller claims it | refused — nothing to read yet |
| claimant (caller pid = owner) | allowed (re-arm, pool change, or release) | allowed |
| any other pid | **refused**, `STATUS_PRIVILEGE_NOT_HELD`, logged | **refused** — a record names another process's destination and pid |
| caller pid 0 | refused | refused |

Two details that matter more than they look:

* **The owner is the caller as the kernel sees it** (`PsGetCurrentProcessId()`), never the
  pid the request claims; a request whose `ProxyPid` disagrees with its caller is refused
  outright rather than believed.
* **Disabling releases the claim** (`TpdrvApplyConfig` stores pid 0 when `Enabled == 0`),
  so the service restarting under a new pid is a normal sequence and not a driver reload.
  A service that *crashed* while holding the claim leaves the driver claimed — recovery is
  `sc stop/start` (Administrator, the same privilege that could reconfigure it anyway),
  and `wfp --verify` names the holding pid instead of leaving the operator to guess.

And the same handler had a **memory-safety** bug next to the trust bug: it bounded the
TCP token array against `InputBufferLength` but never bounded `UdpTokens`, which lives at
the fixed offset 144. A caller sending 16 bytes and claiming 64 UDP tokens made
`TpdrvApplyConfig` `memcpy` ~128 bytes from **past the end of the caller-sized buffer** — a
kernel pool over-read whose value then becomes routing state (the ports the callout
redirects to), not merely garbage. Now `TpdrvConfigBufferOk(inLen, token_count,
udp_token_count)` bounds each array against its own offset, only for the bytes it will
actually read, and it is a pure predicate so the exact offending request shape is pinned in
`test_record.c` (10 checks: the 16-byte/64-udp-token case, boundary fits, over-long counts,
zero counts, empty buffer). The struct offsets the test reasons about come from
`offsetof(TPDRV_CONFIG, …)` rather than literals, and the test asserts they are 16/144/272
so a layout change fails loudly instead of quietly re-opening the hole.

Not done, and worth doing before production: an **SDDL** security descriptor on the device
object (`IoCreateDeviceSecure`), so the check is enforced by the object manager rather
than by code that runs after the open. The pid rule is defence in depth, not a substitute
for access control.

## Publishing the token pools to a lock-free reader

`TpdrvTakeToken` runs inside `classifyFn` at `DISPATCH_LEVEL`, on whatever CPU the
connection landed on, while the service may be pushing a new pool through
`IOCTL_TPDRV_SET_CONFIG` on another. The callout deliberately takes **no lock** on that
path, so the writer is responsible for making a torn read *harmless* rather than
preventing one, in this order:

1. zero the array **beyond** the new count;
2. copy the new contents;
3. publish the count with `InterlockedExchange` (a full barrier).

The consequence is the property `test_record.c` pins: a reader that catches the pools
mid-update sees port **0**, and classify already treats 0 as "no listener configured" and
**permits** the flow — so a race costs one unproxied connection instead of redirecting an
app into a socket from a previous session that nobody owns any more. Publishing the count
*before* the contents (or letting the compiler do that, since the array is not volatile)
would instead expose stale-but-nonzero ports, which are silently wrong routing.

## Verified against the installed headers (not transcribed)

| Claim the driver depends on | Authority | Guard |
|---|---|---|
| `incomingValue[field::IP_PROTOCOL]` is index **5** at *both* connect-redirect layers | `Windows Kits/10/Include/10.0.26100.0/um/fwpsu.h`, enums `FWPS_FIELDS_ALE_CONNECT_REDIRECT_V4` / `_V6` | `wfp_callout_plan::the_installed_header_still_numbers_ip_protocol_at_our_index` re-derives it from that file on every test run (red-tested: changing the constant to 6 fails it) |
| `layout_probe.c` — compiled by `build_cl.ps1`, **never linked into the driver** — asserts the `fwpsk.h` shapes this directory documents: `SOCKADDR_STORAGE` 128, `SOCKADDR_IN` 16, `SOCKADDR_IN6` 28, `FWPS_CONNECT_REQUEST0` 312 with `remoteAddressAndPort`@128 / `localRedirectTargetPID`@264 / `localRedirectContext`@296, `FWP_VALUE0` `type`@0 and `uint64`@8 (a pointer), `FWPS_CLASSIFY_OUT0.rights`@24, the metadata bits (FLOW 0x2, PROCESS_ID **0x20**, REDIRECT_RECORD_HANDLE 0x40000000), `FWPS_RIGHT_ACTION_WRITE` 1, `…_IP_PROTOCOL` 5, and `sizeof(TP_FLOW_RECORD)` 72 | the real headers, at compile time — red-tested: claiming `portBe`@7 or size 313 makes `build_cl.ps1` fail with a named error |
| The `FWP_*` data-type tag values (`UINT8`=1 … `UINT64`=4) the classify switch reads | same SDK headers, via `abi_check.c` | `abi_check` refuses to build on drift |
| `sizeof(SOCKADDR_IN)`=16, `sizeof(SOCKADDR_IN6)`=28, `SOCKADDR_STORAGE`=128 | `ws2ipdef.h` (host-compilable, and the real `fwpsk.h` uses the same types) | `test_record.c` byte checks + the MSVC compile |
| The four signatures this file used to get wrong | `fwpsk.h` / `fwptypes.h` from the WDK package | the MSVC compile itself (`build_cl.ps1`) |

**Only TCP and UDP are redirected.** A flow whose `IP_PROTOCOL` field is anything else
(ICMP, GRE, ESP, or `FWP_EMPTY`) is permitted untouched: the engine has no egress for
those transports, so a redirect would hand their packets to a TCP or UDP token listener and
break a flow that was working. The value is read through a `switch` on `FWP_VALUE0.type`
for the same reason — the union's 64-bit case is a pointer, and the driver runs at
`DISPATCH_LEVEL`. Reference implementation: `trans_proxier::wfp_callout_plan::plan`
(`icmp_is_permitted_rather_than_handed_to_a_tcp_listener` covers it, including that TCP and
UDP must still redirect).

## Build, sign, load

**One command, inside a VM, runs the whole acceptance sequence:**

```powershell
.\vm_check.ps1 -IDeclareIAmInAVM -App <path\to\trans-proxier.exe>
#   build → test certificate → sign → load → arm the route → `wfp --verify`
#   exit 0 = every gate row passed, including "the kernel credited the flow
#   to this process", which is the row no user-mode hook can fake.
.\vm_check.ps1 -IDeclareIAmInAVM -Teardown    # stop the route + unload the driver
```

It refuses to run without `-IDeclareIAmInAVM` — verified by running it on a physical host,
where it throws before touching anything — because each step writes to the machine: the
certificate store, the driver store, the SCM, and then this host's routing for the
whitelisted programs.

```powershell
# or step by step, from an EWDK/Developer prompt with the WDK installed
.\driver_wfp\build_cl.ps1                    # MSVC + WDK km headers → out\tpdrv_wfp.sys (no VS project needed)
.\driver_wfp\build_cl.ps1 -SignWith <pfx> -PfxPassword <pw>
                                             #  + Authenticode-sign + write out\tpdrv_test.cer
.\driver_wfp\build.ps1                       # → driver_wfp\out\tpdrv_wfp.sys (via the .sln settings)
.\driver_wfp\build.ps1 -Sign                 # + self-signed test certificate
.\driver_wfp\install.ps1 -IDeclareIAmInAVM   # pnputil + sc create + start
.\driver_wfp\install.ps1 -Uninstall -IDeclareIAmInAVM
```

`build_cl.ps1 -SignWith` is how the image in this repository was signed: the key came from
OpenSSL into `%LOCALAPPDATA%\trans-proxier-wdk\cert` and was **not** imported into any
certificate store, so the chain reads as untrusted on this host by design. `out\tpdrv_test.cer`
is the public half — import it into `LocalMachine\Root` + `TrustedPublisher` **on the VM**.

Prerequisites for loading: a WDK matching your Windows build, `bcdedit /set testsigning
on` + reboot, and the certificate in LocalMachine *Trusted Root* + *Trusted Publishers*.
Production use needs an EV code-signing certificate and Microsoft attestation signing;
unsigned kernel drivers are refused outright on Windows 10/11.

Then arm it from the service side (every piece below is implemented and tested; only
the driver is missing):

```
set TPROXIER_WFP_INGRESS=1
trans-proxier wfp                                      # preview: installs nothing
trans-proxier wfp --apply --i-consent-to-install-wfp-filters
netsh wfp show state file=wfp-state.xml                # look for callout + filters
```

## Status, honestly

**It has been BUILT.** `.\build_cl.ps1` compiles both translation units with MSVC 14.44 and
links a real driver image — `out\tpdrv_wfp.sys`, 8,704 bytes, `8664 machine (x64)`,
`1 subsystem (Native)`, importing exactly the ten `Fwps*` DDIs plus
`ExAllocatePool2`/`IoCreateDevice`/`IoCreateSymbolicLink` from `fwpkclnt.sys` +
`ntoskrnl.lib`. It has **not** been signed and **never** been loaded, so nothing here
claims the redirect works — only that the code is valid, layout-correct kernel C.

The first real compile was worth exactly what this file promised. Four things my DDI-page
transcription had wrong, all now corrected in both `tpdrv_wfp.c` and `wdk_shim.h`:

| Claimed | Reality (`fwpsk.h` / `fwptypes.h` 10.0.26100) | What it would have done |
|---|---|---|
| `incomingValue[IP_PROTOCOL].value.uint64Data` | `FWP_VALUE0` has **no** such member; its 64-bit case is `UINT64 *uint64` (a pointer), and this field is `FWP_UINT8` | would not have compiled; "fixing" it by taking the wide member would have read a pointer as a protocol number |
| `FWPS_CLASSIFY_HANDLE` type | does not exist — the classify handle is a plain `UINT64` | would not have compiled |
| `FwpsAcquireWritableLayerDataPointer0(…, UINT16 filterId, …)` | `_In_ UINT64 filterId` (matching `FWPS_FILTER1.filterId`) | a silent narrowing of every filter id |
| `status = FwpsApplyModifiedLayerData0(…)` | returns **`void`** | could not have compiled — and it is the reason the action restore must be done by hand on every path |

Reading the real header also settled the one constant I had deliberately left unused
because I refused to guess it: `FWPS_CLASSIFY_FLAG_REAUTHORIZE_IF_MODIFIED_BY_OTHERS` is
`0x00000001`, so the second half of Microsoft's anti-loop recipe is now applied exactly as
documented instead of with a substitute.

`build.ps1 -Test` still runs the WDK-less check (gcc + `wdk_shim.h`) so this directory
remains checkable on a machine without any of the above, and it caught a genuine
inconsistency while the real headers were being incorporated — the driver used the
reauthorize flag before the shim declared it.

Still outside every check available here:

* **run time** — whether the redirect is honoured, whether `localRedirectContext` arrives
  intact through `SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT`, and whether the UDP
  token/flow-delete pairing holds under real flows;
* signing (`build.ps1 -Sign` needs a code-signing certificate; creating and *trusting* one
  changes the machine, so it is an operator action);
* `#pragma alloc_text`/section placement: with no `INIT`-only routine annotations, all code
  is non-paged — correct for a classify callback, wasteful for `DriverEntry`, and worth a
  look once the driver is loaded rather than guessing now.

## Reproducing the build without installing the WDK

`build_cl.ps1` needs only (a) any VS 2022 with the C++ tools — it locates
`vcvars64.bat` through `vswhere.exe` — and (b) a directory holding the WDK's `km` headers
and the kernel import libraries. (b) does **not** require an installer: Microsoft
distributes them as the `Microsoft.Windows.WDK.x64` NuGet package (10.0.26100.6584 here,
110 MB), which is a zip. Extract just what a build touches:

```
c/Include/10.0.26100.0/km/**        → <dir>\include\      (fwpsk.h, ntddk.h, ndis.h, crt\)
c/Lib/10.0.26100.0/km/x64/*.lib     → <dir>\lib\          (fwpkclnt, ntoskrnl, hal,
                                                           bufferoverflowfastfailk, displib, ndis)
.\build_cl.ps1 -WdkDir <dir>        # defaults to %LOCALAPPDATA%\trans-proxier-wdk\wdk
```

Nothing is installed, registered or loaded; the headers and import libraries sit in a
per-user scratch directory and the output is `driver_wfp\out\`.

Rollback is cheap by construction: the filters, sublayer and callout object live in the
service's **dynamic** BFE session, so stopping `trans-proxier` removes them without
touching anyone else's WFP policy. `netsh wfp reset filters` is a last resort, not the
normal way out.
