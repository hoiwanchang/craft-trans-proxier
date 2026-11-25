# trans-proxier — clean-room PE-proxy replica (Rust)

A from-scratch Rust recreation of the original's behaviour and UI,
produced by black-box investigation of the shipped binaries (see the
`craft-anything` investigation ledger: findings `fnd_1..43`). No original code is
copied; originals live under `original/` (git-ignored) and are never run.

> **Honesty first.** Everything marked *verified* below has a passing test. Items
> marked *pending* are real and NOT done — most are blocked on an environment
> only the operator can provide (a live elevated Windows Filtering Platform host,
> an IPv6-capable SOCKS5 egress, or a real desktop to eyeball the GUI). This
> README states exactly where the line is.

## Workspace

| Crate | What | Kind |
|---|---|---|
| `trans-proxier` (root) | engine, rules, config, monitors, SOCKS5/SOCKS4/HTTP, DNS fake-IP, profiles, crypto, WFP control-plane + classify | lib (+ GUI feature) |
| `tpdrv` | the ws2_32 inline-hook DLL (Module Copy) | cdylib, x64 + i686 |
| `tphelper` | cross-bitness broker (calls `InitFilter3`) | bin, x64 + i686 |
| `tpinject` | engine host: named-pipe decision server + relays + the hook, the WFP route, or both (each consent-gated; `--no-hook --wfp` = kernel route only) | bin |
| `tpwfp` | user-mode WFP callout DLL (redirect decision) | cdylib |

## Build & run

```sh
# deps (crates.io) only reachable via the operator's local mixed proxy:
CARGO_HTTP_PROXY=http://127.0.0.1:7890 cargo fetch
# …and the live interception suite in a 32-bit process (the hook ships both bitnesses;
# i686 has its own install path — `push imm32; ret` instead of the 14-byte RIP jump):
CARGO_TARGET_DIR=target_check cargo test -p trans-proxier --no-default-features     --target i686-pc-windows-msvc --test transparent_windows

cargo build --workspace                       # GUI default + all native crates
cargo run                                     # opens the GUI (bare invocation)

# full test suite (unit + integration + a LIVE in-process interception test):
cargo test --workspace
```

Windows x64. `tpdrv`/`tphelper` also build for `i686-pc-windows-msvc` (the
cross-bitness story).

### Important: build in a separate target dir

A past experiment that installed the **global message hook** mapped the old
`tpdrv.dll` into ~33 of the operator's running apps, which keeps
`target/debug/tpdrv.dll` file-locked. Until those apps are closed, the *fixed*
hook cannot be written into `target/debug`. Build/test with:

```sh
CARGO_TARGET_DIR=target_check cargo build --workspace
CARGO_TARGET_DIR=target_check cargo test  --workspace
```

The complete, verified artifact set is in `target_check/debug/` (+ `i686`). To
land them in `target/debug`: close the affected apps (or reboot), then a normal
`cargo build --workspace`.

### …and the stale-DLL trap that masquerades as a broken hook (measured 2026-11-25)

`tpdrv.dll` gets pinned by every process the global message hook has touched. Enumerating
loaded modules on this workstation found it mapped into **301 processes**, from three
builds at once — `target/debug`, `target_check/debug`, and the installed copy at
`D:\ProgramFiles\trans-proxier-win-x64`. So a build can fail like this:

```
error: failed to remove file `…	arget_check\debug	pdrv.dll` … 拒绝访问 (os error 5)
```

and **cargo then runs whatever old DLL is still on that path**. `tests/transparent_windows.rs`
in that state fails `connect(198.51.100.7:80)` with `WSAETIMEDOUT` after 21 s while its own
engine records **zero** flows — which reads exactly like "transparent interception is
broken". I reported it as an environment blocker; that was wrong. With a clean
`CARGO_TARGET_DIR` the same test passes in 2.4 s on this same machine, hook and all.

Three rules, each learned the hard way in one session:

* **Never trust the exit code of a piped cargo run**: `cargo test … | tail` reports
  `tail`'s status. My first "green" hid `cargo_exit=101`.
* **After restoring a file from a backup, `touch` it.** `cp`/`mv` keeps the older mtime,
  so cargo re-runs the *previous* build and the red test you just did looks like it stuck.
* **A locked target dir means the artifact is a lie** — build/test in a directory nothing
  has loaded from (`CARGO_TARGET_DIR=target_probe`) rather than believing the old one.

And the productive one: `TPROXIER_HOOK_DEBUG=1` + `--nocapture` traces every detour
install, naming the export, and `TpdrvHookStatus()` reports which are live as a bitmask.
That is how the vague question "does the DNS hook actually work?" became a number: on the
first run the mask was `0x03fff` — **14 of 15** — and the one missing bit was
`freeaddrinfo`, whose prologue is `48 85 c9` (`test rcx,rcx`) + `74 56` (`je +0x56`): a
near-relative branch inside the first five bytes, so neither patch shape could be stolen
verbatim. Widening that `je` to `0F 84 disp32` on the way into the trampoline (and
demanding a ±2 GiB trampoline whenever a branch is widened, because a `rel32` cannot span
further) closed it: mask `0x07fff`, **15 of 15**, and the live test now executes the
relocated prologue instead of just installing it. All of that is in
`tpdrv/src/decode.rs::displace_widenable` + `install_jmp`.

## What is DONE and how it is verified

| Capability (original feature) | Verified how |
|---|---|
| Bare-launch GUI, zh/en bilingual, tabs→menu shell, live status bar w/ rates, real-time log | compiles+runs; render not screenshot-verified (see Pending) |
| Connection List (Application/Remote/Server/Rule/Proto/Created/Sent/Recv) + filter + Disconnect + **per-app disconnect** + **per-connection "＋Rule" (add proxy rule) / "＋Block" (blacklist) from a live flow** + Delete-row | `monitor` unit tests; `disconnect_aborts_active_relay`, `remove_flow_drops_the_row`, `abort_app_*`, `conn_filter_matches_*`, `rules::rule_from_conn_tests` (4) + `block_rule_from_conn_tests` (2, generated-block-decides + inverse) |
| App **whitelist** gate (fail-closed) | `rules` whitelist tests incl inverses |
| **Global proxification on/off** (Pause) — gate precedes rules/whitelist/IP-leak, mirrored in WFP | `rules::proxification_pause_tests` (3, incl pause-beats-block-and-ip-leak), `config` pause round-trip + inverse key, `wfp_classify` paused-never-redirects |
| Proxy Servers / Chains / Rules editors (CRUD) incl **multi-server/multi-app per rule** (comma/;/whitespace lists) + **port specs (lists + `a-b` ranges + `*`)** + **per-rule Protocol (TCP/UDP/both)** + **Block action**, Options, About, Profiles | wiring audited; `rules::port_spec_tests` (matcher+decision+reversed-range; config round-trip + reject `http`/`99999`), `rules::list_tests` (4, host/app list matching + separators + inverses), `rules` protocol tests, `rules::block_tests` (5), `config` protocol+block round-trip, LIVE `transparent_windows` blocked-connect refused (`…→ 阻止`), `profiles` unit + CLI `profiles` integration tests |
| Profiles new/load/save-as/manage/import/export + **master-password encryption** | `crypto` (ChaCha20-Poly1305 + Argon2id) 5 tests; round-trip incl wrong-pw & tamper rejection |
| Transparent interception (no app-side proxy config) | `tests/transparent_windows.rs` (in-process, **no** global hook) |
| …TCP | live test (connect to `198.51.100.7:80` → SOCKS5 CONNECT → echo) |
| …connected UDP + **unconnected UDP** (`sendto/recvfrom/recv`) + **WSA UDP** (`WSASendTo/WSARecvFrom`, sync) | live tests (SOCKS5 UDP ASSOCIATE round-trips) |
| …**IPv6 UDP** — all four combinations: unconnected (`send_to`), connected (`connect`+`send`), and each of those **overlapped** (event-completion AND IOCP) (`WSARecvFrom`+`OVERLAPPED` pended, completed out-of-line) | live tests: v6 `[::1]` relay round-trip; overlapped recv pended with `WSA_IO_PENDING` then completed via `SetEvent` / `GetQueuedCompletionStatus` (key + OVERLAPPED preserved); v6 destination rides the SOCKS5 UDP frame (ATYP 0x04) |
| …**app DNS (`:53`) through the proxy, TCP *and* UDP — and the UDP path is now proven to be **re-dialled at the operator's configured resolver**, not the app's, with a log line saying so** (`dns_mode=proxy`): a resolver the rules send *Direct* is still tunnelled and dialled at the **configured** resolver, and blocked (never leaked to the OS resolver) when no chain can carry it | `rules::dns_*` (5, incl. the raw-rule-vs-policy divergence that let the TCP relay dial direct), `intercept::dns_*` (resolver rewrite + loopback-stub and hostname-resolver exceptions); LIVE `transparent_windows`: UDP local-vs-proxy on one destination, and a TCP echo whose tunnel log names the rewritten resolver. IPv6 resolvers covered too: the rewrite yields the v6 literal and `socks5` frames it as ATYP 0x04 (16 bytes + network-order port, asserted against bytes a real loopback SOCKS5 peer received) |
| **WFP route armed from the GUI** (the process that actually stays alive): `prepare()` → engine start → `commit()`, filters per whitelisted app (TCP **and** UDP), `Route` drop disarms the driver + withdraws the dynamic session; ticking it on without restarting the engine says so instead of half-arming | `wfp_route` 6 tests (consent/whitelist/driver/listener refusals incl. per-pool wording, pair-count, blank-name trimming) + `tests/wfp_enable_flag.rs` (the runtime latch, in its own binary because the flag is process-global; precondition red-tested by setting the env var) |
| …**IPv6 TCP** (destination *and* upstream proxy) | live test (`[2001:db8::1]` proxified) + `engine_dials_an_ipv6_upstream_proxy` |
| **DNS fake-IP** producer + reverse-map + `getaddrinfo`/`freeaddrinfo` hooks (DNS-then-proxy / hostname rules) | live test: name→fake IP→connect→reverse-map→proxy; `freeaddrinfo` no-crash; gated inert under `dns_mode=local` |
| **HTTP proxy server** (CONNECT + absolute-URI forward) | `http_proxy_forwards_absolute_get_origin_form` + 6 parser tests |
| Egress: HTTP / HTTPS / SOCKS5 / **SOCKS4** / **SOCKS4a** | integration e2e per protocol |
| **Passive DNS observation** (UDP **and** TCP): a name learned from a DNS answer the engine carried is used to match hostname rules against a later connect that arrives as a bare IP — the capability the WFP route needs, since it has no `getaddrinfo` hook | `net_dns::snoop_*` (4, incl. compressed names, NXDOMAIN ignored, pointer loop / over-long label / out-of-range pointer refused), `dns::snoop_tests` (5: name normalisation, TTL honoured + 0 not cached, fake pool never shadowed, bounded with FIFO eviction, garbage ignored), `engine::relay_counted_tap` observes the download direction AFTER forwarding (a non-DNS 200 KB tunnel is provably untouched); LIVE `tests/dns_snoop.rs` (4): query → answer → a **hostname rule** matches the later IP connect, and the SOCKS5 CONNECT the engine sent carries `snooped.example.com:80`, not the IP; plus the negative control (no answer first ⇒ not matched) |
| **IP-leak prevention**, **redundancy recheck**, **proxy timeout**, "do-not-resolve", block-non-AAAA decision | rules/dns/redundancy/engine unit tests incl inverses; `proxy_timeout_secs_is_enforced` |
| …**select() / WSAEventSelect + WSAEnumNetworkEvents** readiness on proxied UDP — readiness is answered from the hook queue (the app socket itself never becomes readable), honouring the caller timeout | live tests: `select()` reports the socket readable and the datagram is then really there; `WSAEventSelect(FD_READ)` wakes and `WSAEnumNetworkEvents` reports FD_READ |
| WFP callout **ingress** (engine half of the redirect contract): token-port pool + `FlowRecord` pipe, fake-IP reverse-map, no guessing on unknown flows | LIVE `tests/wfp_ingress.rs` — the test *is* the driver (stages a record, connects the token, gets a proxied echo); `wfp_ingress` unit tests (staging, TTL, frame layout) |
| WFP callout **driver source** (`driver_wfp/`): C against the real `fwpsk.h` so the WDK compiler validates every member; registers under the shared callout GUID, stashes a `FlowRecord` in `localRedirectContext`, redirects to the engine token port, anti-loop query first, no locks/blocks at DISPATCH_LEVEL; + INF, build.ps1, install/uninstall.ps1 (refuses without an explicit in-a-VM flag) | **never built by the WDK, never loaded** — but no longer un-compiled: both kernel TUs pass `gcc -Wall -Wextra -fsyntax-only` against `driver_wfp/wdk_shim.h` (the `fwpsk.h` declarations, transcribed from the DDI pages) plus MinGW-w64's copy of Microsoft's own `ddk/ntddk.h`, and `build.ps1 -Test` runs it. That check produced six fixes (UDP record read before it was produced, a pool+token leak on the exhausted-table path, a 4-argument call to a 6-parameter function, a missing `FWPS_RIGHT_ACTION_WRITE` restore, `notifyFn` with the wrong signature, and `-Test` being unrunnable without a WDK), and the two red tests that prove the check bites are recorded in `driver_wfp/README.md`. Layout is still the WDK's business, so the driver accesses every kernel struct by name and never by offset. `C_ASSERT`s pin the 72-byte record against the Rust tests; the logic it mirrors is host-tested in `wfp_callout_plan` (7, incl. sockaddr byte order for v4/v6, anti-loop precedence, token-exhaustion ⇒ permit) |
| WFP route **UDP** support (a per-flow token socket, so a redirected datagram app gets its replies back from the port it was sent to) — **including token RECYCLING**: when the driver hands a token back after flow delete, the next app's first packet arrives from the same socket address as the previous flow's payload, so the relay now distinguishes a flow *declaration* from *payload* before reusing an entry, and the source pin rebinds | LIVE in `tests/transparent_windows.rs`: the test stages a record over the ingress pipe, sends a bare datagram into the UDP token, and gets it back through the engine's SOCKS5 UDP ASSOCIATE to the **record's** destination; driver side reserves/looks up/releases per-flow tokens in a spinlock-guarded table (`TpdrvUdpReserve`/`Lookup`/`ReleaseByFlow`) — and the reserve now **refuses** rather than double-books a port, so capacity is the number of distinct token ports (16), not the 64 table slots; the flow association is checked before committing, so a refusal cannot leak the token | host-checked in `test_record.c` (70 checks, incl. "no token port is ever handed to two live flows") and executed end-to-end in `test_classify.c` (115 checks) |
| WFP **control plane** (layer/condition GUIDs, `FWPM_*` layouts, callout-object registration, dynamic session, fail-open filter flag) — plus `trans-proxier wfp` to preview/arm it (consent-gated), `wfp --apply` **supervised** (re-arms the token pool when the driver drifts, disarms on exit), and `wfp --verify` as the acceptance gate, whose last row demands the kernel attributed the flow to *this* process | `wfp::tests::abi_*` pinned against SDK 10.0.26100 headers **and re-checked by an independent C compiler** (`gcc driver_wfp/abi_check.c && ./abi_check` — every size/offset/action/type agrees, and it fails on drift); **`FwpmEngineOpen0` handshake executed against the live BFE** (`cargo test --lib wfp:: -- --ignored`, passes un-elevated: session accepted, sublayer correctly denied); `cli::wfp_verb_tests` (20: dry-run, consent refusal, missing-driver refusal, empty whitelist, happy path, gate-row attribution, incapable-driver refusal, short-status refusal, read-only-report-without-profile, claim-theft refusal, plus the record-ABI, transport-split and preview cases) + the verb run end-to-end on this host |
| `InitFilter3` disassembles identically to `PrxDrvPE64.dll`; real x86-64 instruction-length decoder | `decode` 9 unit tests; ledger evidence |

Test count: **278 Rust green, 0 failed** (x64) — **and the same live interception suite green under `i686-pc-windows-msvc`, with `TpdrvHookStatus` = `0x07fff` (15/15 detours) in both bitnesses** (`cargo test --workspace --no-fail-fast` with
`CARGO_TARGET_DIR=target_probe`, 2026-11-25 — `cargo_exit=0`, not a piped tail's status).
**Trap that produces a false failure:** a third-party app in the session can still hold a
mapping on an older `target_check/debug/tpdrv.dll` (loaded back when a global hook was live),
and then `cargo build` fails that relink with `os error 5` while the *stale* DLL — one without
`TpdrvHookStatus` — stays in place. The live suite's precondition assert then fires
in 0.4 s and reads exactly like a code regression. Check the artifact, not the code: `python -c "print(open('target_check/debug/tpdrv.dll','rb').read().count(b'TpdrvHookStatus'))"` → 0 means stale; run the suite in a target dir nothing has mapped.
Also **185 host-run C checks** in `driver_wfp/`: 70 on the byte encoders, the config-buffer bounds and the control-device authorisation truth table (including a
golden 72-byte buffer asserted identically in both languages) and 115 that execute the
driver's own classify callback + notifyFn — including a 4000-case **invariant sweep** over randomised
rights, metadata flags, protocol encodings, pool contents and prior-redirect states, asserting the
callout never blocks, never rewrites without a recoverable record, never crosses the TCP and UDP
pools and always returns the write right it must (proved able to fail: an injected missing
rights-restore was flagged at iteration 38) (`test_classify.c`, with recorded fakes for the Fwps* DDIs —
IPv6 included, where the redirect target must stay 28 bytes of AF_INET6;
`TpdrvFlowDelete` releasing the UDP token; and `TpdrvNotify` answering success for every
notification type, because a failure there makes the BFE refuse our own filter), plus both kernel TUs type-check and
`layout_probe.c` pins the `fwpsk.h` shapes. A second 72-byte vector is captured from the
bytes the compiled classify path actually emits — in BOTH address families: `test_classify.c` memcmps them and
`wfp_classify.rs` decodes the same buffer, so the kernel↔service contract is pinned by
execution rather than by two readings of the same idea — perturbing one byte on either
side fails exactly one test. 0 warnings, x64 + i686.

## PENDING — what is NOT done, and what you must provide

These are the honest open items. Each is blocked on something only the operator's
environment can supply; none is a silent gap.

1. **GUI / tray visual sign-off.** The shell, Profiles-encryption dialog, Settings
   (IP-leak/tray), HTTP-proxy row and the tray menu compile + are logic-tested,
   but the agent's virtual display renders black (`CopyFromScreen` → 0,0,0), so
   they have **never been seen on screen**. → *Run `target/release/trans-proxier.exe`
   on a real desktop and send screenshots/notes.*

2. **WFP redirect data-plane (the kernel callout).** Everything that can be proven
   without running a driver is now proven: `src/wfp.rs` mirrors the installed Windows
   SDK 10.0.26100 ABI — layer / condition GUIDs, `FWPM_FILTER0`/`FWPM_SUBLAYER0`/
   `FWPM_ACTION0` layouts — with the sizes and offsets pinned by tests, and the filters
   it builds carry `FWP_ACTION_CALLOUT_TERMINATING` because **`FWPM_ACTION0` has no
   redirect field** (the test asserts the struct is `type + GUID`, i.e. a filter alone
   cannot redirect). The per-flow record the driver must stash so the engine can
   recover each flow's ORIGINAL destination is specified and byte-pinned as
   `wfp_classify::FlowRecord`, and the callout GUID is a shared constant
   (`wfp::REDIRECT_CALLOUT`, re-exported as `tpwfp::CALLOUT_KEY`), and the engine
   half is built and **live-tested**, and it follows Microsoft's documented
   proxy handshake rather than an invented one: an accepted, redirected socket is
   asked for its `SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT` (opcodes from
   `shared/mstcpip.h:560-562`) and the `FlowRecord` found there IS the original
   destination, and the redirect records are re-set on the outbound socket
   (`SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS`) — see `wfp_ingress::query_redirect`
   / `apply_records` and their use in `intercept::relay_established`. A token-port +
   named-pipe path (`tproxierWFP`) remains as a fallback for a driver that cannot
   populate the context; it too is live-tested (`tests/wfp_ingress.rs` plays the
   driver). Both are off unless `TPROXIER_WFP_INGRESS=1`, and the hooked path is
   exercised with the query armed so a driver-less build is unchanged.
   The GUI can arm it too now (选项 → 透明代理引擎 → 启用 WFP 内核重定向, with its own
   consent line) via `src/wfp_route.rs`, so the route no longer depends on a
   one-shot CLI process whose filters die when it exits.
   **Update 2026-11-25: the `.sys` is now BUILT here.** `driver_wfp/build_cl.ps1` compiles
   `tpdrv_wfp.c` + `record.c` with MSVC and links `out\tpdrv_wfp.sys` — 8,704 bytes,
   `8664 machine (x64)`, `1 subsystem (Native)`, importing the ten `Fwps*` DDIs from
   `fwpkclnt.sys`. The WDK's `km` headers came from the distributable
   `Microsoft.Windows.WDK.x64` NuGet package (a zip — no installer, nothing registered),
   which disproved this section's earlier claim that `fwpsk.h` was unreachable here. That
   first real compile corrected four wrong signatures (`FWP_VALUE0` has no `uint64Data`;
   no `FWPS_CLASSIFY_HANDLE` typedef; `filterId` is `UINT64`; `ApplyModifiedLayerData0`
   returns `void`) — table in `driver_wfp/README.md`.
   **Signing is done too**: `build_cl.ps1 -SignWith <pfx>` Authenticode-signs the image
   (8,704 → 10,264 bytes; certificate table at offset 8,704 = exactly the image size,
   PKCS#7 `signedData`, `CN=trans-proxier WFP test signing`) and emits `out\tpdrv_test.cer`
   for the VM to trust. The key was made with OpenSSL in a per-user scratch directory and
   **not imported into this machine's certificate stores**, so `Get-AuthenticodeSignature`
   reports an untrusted chain here — the expected state until the `.cer` is imported on the
   test-signing host. What that leaves for the operator's environment is **a test-signing VM
   to load it in** (`bcdedit /set testsigning on`). Nothing has been loaded anywhere, so the
   redirect is unverified at run time. Sessions are `FWPM_SESSION_FLAG_DYNAMIC`, so anything
   this control plane installs disappears when the app exits — see `docs/WFP_ROADMAP.md`.
   → *Load it, then run `trans-proxier wfp --verify`: **every** row passing — including
   "the kernel credited the flow to this process", and (only once a driver answers)
   "no datagram was left unproxied for want of a flow handle" — is what closes this item.
   With no driver loaded the gate prints five rows; the sixth appears when the driver
   answers the status ioctl.*
   What the WFP route would still add over the hook is **process** coverage, not
   socket-style coverage (services, console apps with no message pump, processes
   started before install, cross-integrity targets): TCP, UDP connected/unconnected,
   WSA + overlapped + `select`/`WSAEventSelect` driven sockets and IPv6 are all
   handled by the hook now.

3. **Cross-process (real browser) confirmation of the DNS fake-IP path.** The producer
   is no longer deferred and no longer unsafe: with `freeaddrinfo` hookable again, the
   in-process live test asserts the pair both ways — name → 198.18/15 → proxy when the
   pair is complete, and *refusal* to hand out our node when it is not (`TpdrvHookStatus`
   bit 14 decides, so a host where that detour cannot install loses the feature rather
   than corrupting the caller's heap). What has NOT been seen from here is a real browser
   resolving a name on the user's desktop with `dns_mode = proxy`.
   → *Run `target_probe/debug/trans-proxier.exe`, enable 透明引擎 with consent, and check
   实时日志 for `DNS-UDP fake IP:` lines next to the proxied hostname.*

   (Correction kept on purpose: an earlier version of this section blamed the running
   installed copy for a failing live test. It was a stale `tpdrv.dll` in a locked target
   directory — see the trap section above. Nothing about the machine needed fixing.)
## Safety constraints honoured

- **The callout driver authenticates its control channel.** Opening the device is not
  restricted to the proxy, so an early draft let any local process claim the redirect
  target. Now only the claiming pid may (re)configure or query flows; the owner is the
  caller as the kernel sees it, disabling releases the claim, and refusals are logged.
  Truth table in `driver_wfp/README.md`, executed by `test_record.c`. The same review
  found and fixed a **pool over-read** in that handler (the UDP token array was never
  bounded by `InputBufferLength`, so 16 bytes + a claim of 64 tokens made the driver read
  ~128 bytes of adjacent pool into its routing state); the bounds check is now a pure
  predicate with the offending request shape pinned as a test.

- Clean-room: analysis + recreation only; originals never run; nothing from
  `original/` or the original installer archive is committed (see `.gitignore`).
- The global message hook / WFP filters are **never** installed in the operator's
  live session without an explicit consent flag (`--i-consent-to-install-global-hook`,
  the GUI 启动 consent checkbox); cross-process proof is done **in-process** only.
- The `wfp --verify` acceptance gate refuses to report green on measurements it did not
  take, which is the only defence when the decisive step happens in a VM nobody here
  can reach:
  * the driver row requires `callouts_registered >= 1` AND a valid redirect handle, so
    a `.sys` whose `DriverEntry` failed part-way cannot PASS - it would answer the
    status IOCTL, allow the filters to install, and then permit everything DIRECT;
  * a status reply SHORTER than the 32-byte struct is an error, not a zero: the
    unwritten tail would have read as `udp_untrackable = 0`, which is the passing value;
  * an empty whitelist no longer blocks the read-only rows, so a fresh VM gets an
    answer before it has a profile (installing filters still refuses);
  * a consenting `--verify` hands the driver ITS OWN token pool and keeps the dynamic
    session open across the probe - without both, the two decisive rows could never
    pass in any process - but it refuses to take the claim from a driver another
    process already armed, since that would repoint live flows at listeners that
    vanish when the diagnostic exits. The arming decision is a pure function, so this
    refusal is unit-tested; `vm_check.ps1` runs the gate alone for the same reason.
- `tpinject --no-hook --wfp --i-consent-to-install-wfp-filters` runs the engine with
  **no** global hook at all: only the WFP kernel route, which is the path that covers
  services, console apps with no message pump, and processes started before a hook
  could load. It refuses to start that way without `--wfp`, because a run with
  neither interception mechanism would silently proxify nothing.
- No secrets/cookies/personal data in notes, findings, or handoffs.
- Crypto is real (`chacha20poly1305` + `argon2`), not homegrown.

### 注入的安全模型（2026-11-25 事故后重写）

一次真实故障：操作者的 session 里同时存在 **5 个构建的 tpdrv.dll**（4 个构建目录 + 1 个安装目录），
92 个进程被注入，其中 65 个进程里同一个 ws2_32 函数被叠了 5 层 inline detour，
表现为"几乎所有软件都崩"。根因是当时既没有**归属检查**，也没有**改写范围限制**，
更没有**还原能力**——摘钩只摘钩子，detour 要等进程重启才消失。

现在的四条规则，全部有测试：

| 机制 | 载体 | 作用 |
|---|---|---|
| 改写范围 | `Local\TpDrvCtl` 控制块（引擎创建并写入） | 名单里的映像才允许被 patch；**名单外进程一字节不改**。白名单开启但为空 = 谁都不改（fail-closed），显式关闭白名单才写 `*` |
| 单一主人 | `Local\TpDrvHookOwner` 命名互斥体 | 第二个实例调 `InitFilter3` 直接被拒（返回 NULL，引擎报 183），杜绝叠加 |
| 可还原 | 补丁账本 `(地址, 长度, 原始字节)` | `install_jmp` 写之前先记账；`TpdrvRemove()` / 停止时广播 `teardown` 让**已注入进程自行还原**，不必重启 |
| 不拖死宿主 | `fenced()` 包住 `intercept`/`udp_send`/`udp_recv` | panic 变成"这条不拦截"，代价是一个 socket 走直连，而不是宿主进程 abort |

还原通路之所以能到达已经注入的进程：`carrier_proc` 是唯一在我们与那些进程
再无句柄关系时仍会执行的代码，所以它兼任拆除信道（每秒最多读一次控制块）。
`TpdrvPatchedCount()` 用来证明"真的还原了"，而不是"调用发过了"。

已存在的限制（不粉饰）：

- 全局消息钩子本身仍会让 Windows 把 DLL **映射**进所有泵消息的进程 —— 映射不再
  等于改写，但内存里仍会有这份镜像；彻底避免映射需要改为按 PID 注入。
- 本次修复**救不了已经在跑的旧副本**：崩溃过的进程仍需重启一次才会干净。
- Firefox 那类 panic 的**根因仍未定位**；围栏只让它不再致命，`%LOCALAPPDATA%\
  trans-proxier\tpdrv-hook.log` 会记下第一个真正触发的站点。

