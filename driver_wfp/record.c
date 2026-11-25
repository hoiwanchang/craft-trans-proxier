/*
 * record.c — the redirect callout's byte-level output, host-compilable on purpose.
 *
 * Nothing here includes fwpsk.h: the functions take plain sockaddrs, which is what
 * FWPS_CONNECT_REQUEST0 contains anyway. That means the risky part of a redirect
 * driver — endianness, sockaddr layout, the 72-byte context the proxy will parse —
 * can be built and executed with an ordinary C compiler and checked here, instead of
 * first on a test-signing VM. See test_record.c.
 *
 * The values asserted below are the same ones trans_proxier::wfp_callout_plan asserts
 * in Rust; the two implementations have to agree with each other and with
 * wfp_classify::FlowRecord, which is what the C_ASSERTs in tpdrv_wfp.c pin.
 */
/*
 * One include block differs between the kernel build and the host build. In the
 * kernel, these types come in via <ntddk.h>/<fwpsk.h>; if cl.exe reports
 * PSOCKADDR_STORAGE unknown, add <netioapi.h> HERE and nowhere else — the rest of
 * the file is identical in both worlds, which is the whole point of keeping the
 * encoders out of the driver proper.
 */
#ifdef TPDRV_SYNTAX_CHECK
/* no kernel headers and no user-mode winsock here: wdk_shim.h (force-included by the
 * syntax-check command) carries both halves, because ntddk.h and winsock2.h cannot
 * appear in the same translation unit. */
#elif defined(_NTDDK_)
#include <ndis.h>
#include <fwpsk.h>
#else
#include <winsock2.h>
#endif

#ifndef TPDRV_SYNTAX_CHECK
#include <ws2def.h>
#include <ws2ipdef.h>
#endif

#include <string.h>
#include <stddef.h>
#include "record.h"

/*
 * Network order without depending on a kernel helper: these are the only two byte
 * swaps the redirect path performs, and writing them out keeps the intent visible in
 * the disassembly of a review.
 */
static UINT16
TpHtons(
    _In_ UINT16 HostShort
    )
{
    return (UINT16)((HostShort << 8) | (HostShort >> 8));
}

static UINT32
TpHtonl(
    _In_ UINT32 HostLong
    )
{
    return ((HostLong & 0x000000FFU) << 24) |
           ((HostLong & 0x0000FF00U) << 8)  |
           ((HostLong & 0x00FF0000U) >> 8)  |
           ((HostLong & 0xFF000000U) >> 24);
}

/* --- configuration pushed by the service ---------------------------------- */

static volatile LONG  g_TpEnabled = 0;
#define g_TpEnabledRef g_TpEnabled   /* same storage; named for the exchange */
static ULONG          g_TpProxyPid = 0;
static UINT16         g_TpTokens[TPDRV_MAX_TOKENS];
static volatile LONG g_TpTokenCount = 0;
static UINT16         g_TpUdpTokens[TPDRV_MAX_TOKENS];
static volatile LONG g_TpUdpTokenCount = 0;
static volatile LONG g_TpTokenNext = 0;   /* LONG: InterlockedIncrement takes PLONG */

/* moved up: TpdrvApplyConfig publishes the pools under this same lock */
#ifdef _NTDDK_
static KSPIN_LOCK g_TpFlowLock;
#define TP_LOCK()     KIRQL _prevIrql = KeAcquireSpinLockRaiseToDpc(&g_TpFlowLock)
#define TP_UNLOCK()   KeReleaseSpinLock(&g_TpFlowLock, _prevIrql)
#else
#define TP_LOCK()     (void)0
#define TP_UNLOCK()   (void)0
#endif

void
TpdrvApplyConfig(
    _In_ ULONG ProxyPid,
    _In_ ULONG Enabled,
    _In_reads_(TokenCount) const UINT16* Tokens,
    _In_ ULONG TokenCount,
    _In_reads_(UdpTokenCount) const UINT16* UdpTokens,
    _In_ ULONG UdpTokenCount
    )
{
    /*
     * A disabled driver holds no claim: the pid that armed it may have gone away, and
     * the next instance starts with a different one. Keeping the stale owner would turn
     * a clean restart into "restart the kernel service as Administrator".
     */
    g_TpProxyPid = Enabled ? ProxyPid : 0;
    if (TokenCount > TPDRV_MAX_TOKENS)
    {
        TokenCount = TPDRV_MAX_TOKENS;
    }
    if (UdpTokenCount > TPDRV_MAX_TOKENS)
    {
        UdpTokenCount = TPDRV_MAX_TOKENS;
    }
    {
        /*
         * classifyFn reads these pools at DISPATCH_LEVEL with no lock (deliberately: a
         * spin lock in the per-connect path is the kind of cost a redirect callout
         * should not pay), so the writer has to make a torn read HARMLESS instead of
         * preventing one. Three rules, in this order:
         *
         *   1. zero the tail beyond the new count — a reader that indexes past the new
         *      pool therefore sees port 0, which classify already treats as "no listener
         *      configured" and PERMITS, instead of an old port from the previous
         *      session (which would redirect an app into a socket nobody owns);
         *   2. copy the contents before publishing the count;
         *   3. publish the count with InterlockedExchange, a full barrier — otherwise the
         *      compiler may sink the memcpy and hoist the count, letting a reader pick a
         *      fresh count against a stale array.
         *
         * The lock below is the SAME one the flow table uses, so a reconfiguration cannot
         * interleave with a reservation.
         */
        ULONG i;
        TP_LOCK();
        for (i = TokenCount; i < TPDRV_MAX_TOKENS; i++)
        {
            g_TpTokens[i] = 0;
            g_TpUdpTokens[i] = 0;
        }
        if (Tokens != NULL && TokenCount > 0)
        {
            memcpy((void*)g_TpTokens, Tokens, TokenCount * sizeof(UINT16));
        }
        if (UdpTokens != NULL && UdpTokenCount > 0)
        {
            memcpy((void*)g_TpUdpTokens, UdpTokens, UdpTokenCount * sizeof(UINT16));
        }
#ifdef _NTDDK_
        (void)InterlockedExchange(&g_TpTokenCount, (LONG)TokenCount);
        (void)InterlockedExchange(&g_TpUdpTokenCount, (LONG)UdpTokenCount);
        (void)InterlockedExchange(&g_TpEnabledRef, (LONG)(Enabled ? 1 : 0));
#else
        g_TpTokenCount = (LONG)TokenCount;
        g_TpUdpTokenCount = (LONG)UdpTokenCount;
        g_TpEnabled = Enabled ? 1 : 0;
#endif
        TP_UNLOCK();
    }
}

/*
 * Round-robin, no in-use bookkeeping: the token port only selects which of the
 * service's listeners receives the connection, and each accepted socket carries its
 * own redirect context, so two flows on one token cannot be confused for each other.
 * That is also why this runs at DISPATCH_LEVEL without a lock.
 */
UINT16
TpdrvTakeToken(
    _In_ BOOLEAN IsUdp
    )
{
    /*
     * TCP flows share the listener pool: an accepted socket carries its own redirect
     * context, so two flows on one port cannot be confused. UDP cannot, because a
     * connected datagram socket only accepts replies from the port it was sent to —
     * so every UDP flow needs a token of its own, and the driver must release it in
     * its flow-delete callback.
     */
    /* read the count once: re-reading it after the modulo could divide by a different
     * pool size than the one the index was computed against */
    LONG raw = IsUdp ? g_TpUdpTokenCount : g_TpTokenCount;
    const UINT16* pool = IsUdp ? g_TpUdpTokens : g_TpTokens;
    ULONG count, index;

    if (raw <= 0)
    {
        return 0;
    }
    count = (raw > (LONG)TPDRV_MAX_TOKENS) ? (ULONG)TPDRV_MAX_TOKENS : (ULONG)raw;
    if (!g_TpEnabled)
    {
        return 0;
    }
#ifdef _NTDDK_
    index = (ULONG)InterlockedIncrement(&g_TpTokenNext) % count;
#else
    index = (ULONG)(++g_TpTokenNext) % count;
#endif
    /* a zero here is the writer's deliberate signal (tail zeroed, count published
     * last), and the caller treats port 0 as "no listener": permit, never redirect */
    return pool[index];
}

BOOLEAN
TpdrvConfigMayBeSetBy(
    _In_ ULONG CallerPid,
    _In_ ULONG OwnerPid
    )
{
    if (CallerPid == 0)
    {
        return FALSE;               /* nothing is authorised by being pid 0 */
    }
    return (OwnerPid == 0 || CallerPid == OwnerPid) ? TRUE : FALSE;
}

BOOLEAN
TpdrvMayQueryFlow(
    _In_ ULONG CallerPid,
    _In_ ULONG OwnerPid
    )
{
    /*
     * A flow record names another process's original destination and pid, so this is
     * reader-restricted even when the reader is not trying to reconfigure anything:
     * only the claimant, and only while a claim exists.
     */
    return (OwnerPid != 0 && CallerPid == OwnerPid) ? TRUE : FALSE;
}

/*
 * offsetof rather than the WDK's UFIELD_OFFSET: this file is compiled by an ordinary
 * host compiler as well as the kernel one, and the two agree byte for byte because
 * TPDRV_CONFIG is #pragma pack(1) (asserted in test_record.c).
 */
#define TPDRV_CFG_OFF(field) ((ULONG)offsetof(TPDRV_CONFIG, field))

BOOLEAN
TpdrvConfigBufferOk(
    _In_ ULONG InLen,
    _In_ ULONG TokenCount,
    _In_ ULONG UdpTokenCount
    )
{
    if (TokenCount > TPDRV_MAX_TOKENS || UdpTokenCount > TPDRV_MAX_TOKENS)
    {
        return FALSE;
    }
    if (InLen < TPDRV_CFG_OFF(Tokens))
    {
        return FALSE;
    }
    /*
     * Bound only what is actually READ: with a count of zero the driver touches nothing
     * in that array, so requiring the buffer to reach it would reject a valid (if
     * pointlessly small) request.
     */
    if (TokenCount > 0 &&
        InLen < TPDRV_CFG_OFF(Tokens) + TokenCount * (ULONG)sizeof(UINT16))
    {
        return FALSE;
    }
    /* the UDP array lives at its own fixed offset — this is the check that was missing */
    if (UdpTokenCount > 0 &&
        InLen < TPDRV_CFG_OFF(UdpTokens) + UdpTokenCount * (ULONG)sizeof(UINT16))
    {
        return FALSE;
    }
    return TRUE;
}

ULONG
TpdrvEnabled(VOID)
{
    return (ULONG)g_TpEnabled;
}

ULONG
TpdrvProxyPid(VOID)
{
    return g_TpProxyPid;
}

ULONG
TpdrvTokenCount(VOID)
{
    return g_TpTokenCount;
}

ULONG
TpdrvUdpTokenCount(VOID)
{
    return g_TpUdpTokenCount;
}

/*
 * ─── UDP flow table ─────────────────────────────────────────────────────────
 *
 * A redirected TCP connection is self-describing: the service accepts a socket and
 * asks IT for the redirect context. There is no such handle for a datagram — the
 * service just receives a packet on a token port — so the driver has to remember
 * the mapping, and remember which token belongs to which flow so flowDelete can
 * release it. That bookkeeping is the whole difference, and it lives here because
 * it is pure logic that can be exercised without a kernel.
 *
 * Locking: at DISPATCH_LEVEL (classify) a spin lock is mandatory; the host build
 * is single-threaded so the lock compiles away, which keeps the table testable
 * without pretending concurrency away.
 */
static TP_FLOW_ENTRY g_TpFlowTable[TPDRV_MAX_TOKENS];
static volatile LONG g_TpUdpUntrackable = 0;

void
TpdrvNoteUdpUntrackable(VOID)
{
    /* same split as the token cursor: the kernel build must not touch non-atomically */
#ifdef _NTDDK_
    (void)InterlockedIncrement(&g_TpUdpUntrackable);
#else
    g_TpUdpUntrackable++;
#endif
}

ULONG
TpdrvUdpUntrackable(VOID)
{
    return (ULONG)g_TpUdpUntrackable;
}

/*
 * Claim a UDP token for a flow and build its record. Returns 0 when the pool is
 * exhausted — the caller must then PERMIT the flow untouched: half-redirecting a
 * datagram with nowhere to look it up later is worse than not redirecting it.
 */
UINT16
TpdrvUdpReserve(
    _In_ UINT64 FlowHandle,
    _In_ const PSOCKADDR_STORAGE Remote,
    _In_ const PSOCKADDR_STORAGE Local,
    _In_ ULONG Proto,
    _In_ ULONG Pid,
    _Out_ PTP_FLOW_RECORD OutRecord
    )
{
    UINT16 token = 0;
    ULONG i;

    TP_LOCK();
    for (i = 0; i < TPDRV_MAX_TOKENS; i++)
    {
        if (!g_TpFlowTable[i].inUse)
        {
            break;
        }
    }
    if (i < TPDRV_MAX_TOKENS)
    {
        /*
         * The token must be one that NO other live flow already holds. Two reasons, both
         * from how the service uses it: a redirected datagram's destination is resolved
         * BY TOKEN PORT, and a connected UDP socket only accepts replies from the port it
         * was redirected to. Handing one port to two flows therefore does not share the
         * load, it makes the second flow's traffic undeliverable. The table is sized at
         * TPDRV_MAX_TOKENS while the service binds far fewer UDP listeners, so the real
         * capacity is the number of DISTINCT token ports — reserve refuses rather than
         * double-books one.
         */
        ULONG n = g_TpUdpTokenCount;
        ULONG start = n ? ((ULONG)g_TpTokenNext++) % n : 0;
        ULONG k;

        for (k = 0; k < n && token == 0; k++)
        {
            UINT16 candidate = g_TpUdpTokens[(start + k) % n];
            ULONG j;
            BOOLEAN taken = FALSE;
            for (j = 0; j < TPDRV_MAX_TOKENS; j++)
            {
                if (g_TpFlowTable[j].inUse && g_TpFlowTable[j].tokenPort == candidate)
                {
                    taken = TRUE;
                    break;
                }
            }
            if (!taken)
            {
                token = candidate;
            }
        }

        if (token != 0)
        {
            g_TpFlowTable[i].inUse = 1;
            g_TpFlowTable[i].flowHandle = FlowHandle;
            g_TpFlowTable[i].tokenPort = token;
            TpdrvBuildRecord(&g_TpFlowTable[i].record, Remote, Local, Proto, Pid, token);
            *OutRecord = g_TpFlowTable[i].record;
        }
    }
    TP_UNLOCK();
    return token;
}

/* Look a staged record up by the token port a datagram arrived on. */
BOOLEAN
TpdrvUdpLookup(
    _In_ UINT16 TokenPort,
    _Out_ PTP_FLOW_RECORD OutRecord
    )
{
    ULONG i;
    BOOLEAN found = FALSE;

    TP_LOCK();
    for (i = 0; i < TPDRV_MAX_TOKENS; i++)
    {
        if (g_TpFlowTable[i].inUse && g_TpFlowTable[i].tokenPort == TokenPort)
        {
            *OutRecord = g_TpFlowTable[i].record;
            found = TRUE;
            break;
        }
    }
    TP_UNLOCK();
    return found;
}

/*
 * Release the token a finished flow was holding, keyed by the flow context the driver
 * stored with FwpsFlowAssociateContext0 (which is what makes flowDelete actionable).
 * Returns the released port, or 0 if nothing matched.
 */
UINT16
TpdrvUdpReleaseByFlow(
    _In_ UINT16 TokenPort
    )
{
    ULONG i;
    UINT16 released = 0;

    TP_LOCK();
    for (i = 0; i < TPDRV_MAX_TOKENS; i++)
    {
        if (g_TpFlowTable[i].inUse && g_TpFlowTable[i].tokenPort == TokenPort)
        {
            released = g_TpFlowTable[i].tokenPort;
            memset(&g_TpFlowTable[i], 0, sizeof(g_TpFlowTable[i]));
            break;
        }
    }
    TP_UNLOCK();
    return released;
}

ULONG
TpdrvUdpActiveFlows(VOID)
{
    ULONG i, n = 0;

    TP_LOCK();
    for (i = 0; i < TPDRV_MAX_TOKENS; i++)
    {
        if (g_TpFlowTable[i].inUse)
        {
            n++;
        }
    }
    TP_UNLOCK();
    return n;
}

BOOLEAN
TpdrvIsLoopbackRemote(
    _In_ const PSOCKADDR_STORAGE Remote
    )
{
    if (Remote->ss_family == AF_INET)
    {
        const IN_ADDR a = ((const PSOCKADDR_IN)Remote)->sin_addr;
        return a.S_un.S_un_b.s_b1 == 127 ? TRUE : FALSE;
    }
    if (Remote->ss_family == AF_INET6)
    {
        const UINT8* b = (const UINT8*)&((const PSOCKADDR_IN6)Remote)->sin6_addr;
        int i;
        for (i = 0; i < 15; i++)
        {
            if (b[i] != 0)
            {
                return FALSE;
            }
        }
        return b[15] == 1 ? TRUE : FALSE;
    }
    return FALSE;
}

void
TpdrvBuildRecord(
    _Out_ PTP_FLOW_RECORD Record,
    _In_ const PSOCKADDR_STORAGE Remote,
    _In_ const PSOCKADDR_STORAGE Local,
    _In_ ULONG Proto,
    _In_ ULONG Pid,
    _In_ UINT16 TokenPort
    )
{
    /* port fields stay in network order (as they arrived); everything else is host order */
    memset(Record, 0, sizeof(*Record));
    Record->magic = TP_FLOW_RECORD_MAGIC;
    Record->verdict = TP_VERDICT_REDIRECT;
    Record->proto = (UINT8)Proto;
    Record->tokenPort = TokenPort;
    Record->pid = Pid;
    Record->chain = 0;          /* the service picks the chain from the profile */

    if (Remote->ss_family == AF_INET6)
    {
        const PSOCKADDR_IN6 r = (const PSOCKADDR_IN6)Remote;
        Record->family = AF_INET6;
        Record->portBe = (UINT16)r->sin6_port;
        memcpy(Record->addr, r->sin6_addr.u.Byte, 16);
    }
    else
    {
        const PSOCKADDR_IN r = (const PSOCKADDR_IN)Remote;
        Record->family = AF_INET;
        Record->portBe = (UINT16)r->sin_port;
        memcpy(Record->addr, &r->sin_addr.S_un.S_addr, 4);
    }

    if (Local->ss_family == AF_INET6)
    {
        const PSOCKADDR_IN6 l = (const PSOCKADDR_IN6)Local;
        memcpy(Record->localAddr, l->sin6_addr.u.Byte, 16);
        Record->localPortBe = (UINT16)l->sin6_port;
    }
    else
    {
        const PSOCKADDR_IN l = (const PSOCKADDR_IN)Local;
        memcpy(Record->localAddr, &l->sin_addr.S_un.S_addr, 4);
        Record->localPortBe = (UINT16)l->sin_port;
    }
}

/*
 * Loopback, same address family as the original destination. A v6 flow redirected
 * through a 16-byte v4 sockaddr is the classic silent failure here: the stack reads
 * the family first and would then misread every following byte.
 */
void
TpdrvSetRedirectTarget(
    _Inout_ PSOCKADDR_STORAGE RemoteAndPort,
    _In_ UINT16 TokenPort
    )
{
    if (RemoteAndPort->ss_family == AF_INET6)
    {
        PSOCKADDR_IN6 t = (PSOCKADDR_IN6)RemoteAndPort;
        memset(t, 0, sizeof(*t));
        t->sin6_family = AF_INET6;
        t->sin6_port = (unsigned short)TpHtons(TokenPort);
        t->sin6_addr.u.Byte[15] = 1;                       /* ::1 */
    }
    else
    {
        PSOCKADDR_IN t = (PSOCKADDR_IN)RemoteAndPort;
        memset(t, 0, sizeof(*t));
        t->sin_family = AF_INET;
        t->sin_port = (unsigned short)TpHtons(TokenPort);
        t->sin_addr.S_un.S_addr = TpHtonl(0x7F000001UL);   /* 127.0.0.1 */
    }
}
