/*
 * record.h — the byte-level output of the redirect callout, kept free of kernel
 * headers so it can be COMPILED AND RUN on a normal machine (test_record.c).
 *
 * This is the part of a redirect driver where a mistake is silent: a port left in
 * host byte order, a family written in the wrong half of a sockaddr, or a field at
 * the wrong offset all produce a driver that loads and then sends traffic to the
 * wrong place (or nowhere). So the encoding lives here, and the kernel file only
 * hands it the two sockaddrs it got from FwpsAcquireWritableLayerDataPointer0.
 */
#ifndef _TPDRV_RECORD_H_
#define _TPDRV_RECORD_H_

/* types only: the kernel TU gets them from ntddk/fwpsk, the host TU from winsock2 */
#ifndef _NTDDK_
#include <winsock2.h>
#endif
#ifndef TPDRV_SYNTAX_CHECK
#include <ws2def.h>
#include <ws2ipdef.h>
#endif

#include "tpdrv_wfp.h"

/*
 * Control-device authorisation. Opening \Device\TpDrvWfp is not restricted to the
 * proxy, so without a claim rule ANY local process could push a token pool and its own
 * pid and have the callout hand it every whitelisted app's connections — a driver that
 * "works" while silently becoming a redirector for an attacker. The rule is deliberately
 * simple enough to be tested here rather than reasoned about in kernel context:
 *
 *   · pid 0 never wins anything;
 *   · an UNCLAIMED driver (owner pid 0) is claimed by whoever configures it first;
 *   · once claimed, only the claimant may change or clear it. Everyone else is refused.
 *     Releasing therefore requires the claimant: a foreign process must not be able to
 *     switch proxification off (nor on) for someone else's session.
 *
 * Recovery from a service that died while holding the claim is `sc stop/start` (needs
 * Administrator, and DriverEntry starts unclaimed), which is the same trust level that
 * could overwrite the configuration anyway.
 */
BOOLEAN TpdrvConfigMayBeSetBy(_In_ ULONG CallerPid, _In_ ULONG OwnerPid);

/*
 * Does the caller's buffer actually contain the two token arrays it claims?
 *
 * `Tokens` and `UdpTokens` are FIXED-SIZE members at offsets 16 and 144, so each used
 * prefix has to be checked against ITS OWN offset — bounding the TCP array does not
 * bound the UDP array, and an unchecked UdpTokenCount makes the driver memcpy up to
 * 128 bytes from past the end of a buffer sized to InputBufferLength. In kernel that is
 * a pool over-read whose result becomes routing state (the ports the callout redirects
 * to), so it is validated here, before anything is read.
 *
 * Returns FALSE on any over-long count as well, because TpdrvApplyConfig clamps rather
 * than rejecting and a silent clamp would let a truncated request take effect.
 */
BOOLEAN TpdrvConfigBufferOk(_In_ ULONG InLen, _In_ ULONG TokenCount, _In_ ULONG UdpTokenCount);
BOOLEAN TpdrvMayQueryFlow(_In_ ULONG CallerPid, _In_ ULONG OwnerPid);

/* configuration the service pushed (pid + token listeners + master switch) */
void
TpdrvApplyConfig(
    _In_ ULONG ProxyPid,
    _In_ ULONG Enabled,
    _In_ const UINT16* Tokens,
    _In_ ULONG TokenCount,
    _In_ const UINT16* UdpTokens,
    _In_ ULONG UdpTokenCount
    );

/* next free token port of the requested kind, or 0 if none is configured.
 * IsUdp: datagram flows need a token each (a connected UDP socket only accepts
 * replies from the port it was redirected to); stream flows may share a listener. */
UINT16 TpdrvTakeToken(BOOLEAN IsUdp);

/* Datagrams refused because the engine gave us no flow handle to track a token with.
 * Counted, not merely permitted, so the operator can see it in `wfp --verify`. */
void  TpdrvNoteUdpUntrackable(VOID);
ULONG TpdrvUdpUntrackable(VOID);

/* read-only view of the configuration, for the status IOCTL */
ULONG TpdrvEnabled(VOID);
ULONG TpdrvProxyPid(VOID);
ULONG TpdrvTokenCount(VOID);
ULONG TpdrvUdpTokenCount(VOID);

/* fill the redirect context (the proxy reads it back verbatim) */
void
TpdrvBuildRecord(
    _Out_ PTP_FLOW_RECORD Record,
    _In_ const PSOCKADDR_STORAGE Remote,
    _In_ const PSOCKADDR_STORAGE Local,
    _In_ ULONG Proto,
    _In_ ULONG Pid,
    _In_ UINT16 TokenPort
    );

/* rewrite a connect request's remote endpoint to the loopback token listener */
void
TpdrvSetRedirectTarget(
    _Inout_ PSOCKADDR_STORAGE RemoteAndPort,
    _In_ UINT16 TokenPort
    );

UINT16
TpdrvUdpReserve(
    _In_ UINT64 FlowHandle,
    _In_ const PSOCKADDR_STORAGE Remote,
    _In_ const PSOCKADDR_STORAGE Local,
    _In_ ULONG Proto,
    _In_ ULONG Pid,
    _Out_ PTP_FLOW_RECORD OutRecord
    );

BOOLEAN
TpdrvUdpLookup(
    _In_ UINT16 TokenPort,
    _Out_ PTP_FLOW_RECORD OutRecord
    );

UINT16 TpdrvUdpReleaseByFlow(_In_ UINT16 TokenPort);
ULONG  TpdrvUdpActiveFlows(VOID);

/* a connect that is already going to a local proxy must not be redirected */
BOOLEAN
TpdrvIsLoopbackRemote(
    _In_ const PSOCKADDR_STORAGE Remote
    );

#endif /* _TPDRV_RECORD_H_ */
