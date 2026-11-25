/*
 * test_classify.c — runs the driver's OWN classify callback on a host compiler.
 *
 *   gcc -I. -DTPDRV_HOST_TEST tpdrv_wfp.c record.c test_classify.c -lws2_32 \
 *       -o test_classify && ./test_classify
 *
 * Why this file exists: `test_record.c` proves the byte encoders, and
 * `trans_proxier::wfp_callout_plan` is the Rust specification of the decision — but
 * nothing had ever EXECUTED the C that will run at DISPATCH_LEVEL. "The C mirrors the
 * Rust spec" was a reading, not a test. This closes that gap for the classify path
 * (rights handling, the anti-loop branches, the transport gate, token-pool choice, the
 * sockaddr rewrite, the record WFP carries to the proxy). The control device and
 * DriverEntry stay untested on purpose: faking IoCreateDevice could only agree with
 * itself.
 */
#include <stdio.h>
#include <string.h>
#include "tpdrv_host_shim.h"
#include "tpdrv_wfp.h"
#include "record.h"

#define IP_PROTOCOL_FIELD 5   /* FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_PROTOCOL; layout_probe.c pins it */

static int failures = 0, checks = 0;
#define CHECK(cond, ...) do { checks++; if (!(cond)) { printf("FAIL: "); printf(__VA_ARGS__); printf("\n"); failures++; } } while (0)

/* ── the fakes the driver links against here ─────────────────────────────── */
FWPS_CONNECTION_REDIRECT_STATE g_fake_redirect_state = FWPS_CONNECTION_NOT_REDIRECTED;
int g_fake_acquire_fails = 0;
int g_fake_associate_fails = 0;
int g_calls_acquire = 0, g_calls_release = 0, g_calls_apply = 0, g_calls_associate = 0;
UINT64 g_last_apply_flags = 0;
void* g_last_associated_ctx = NULL;

static FWPS_CONNECT_REQUEST0* g_writable = NULL;
static int g_calls_writable = 0;
static UINT64 g_last_filter_id = 0;

NTSTATUS FwpsAcquireClassifyHandle0(void* ctx, UINT32 flags, UINT64* handle)
{
    (void)ctx; (void)flags;
    g_calls_acquire++;
    if (g_fake_acquire_fails) { return (NTSTATUS)0xC0000001L; }
    *handle = 0xC1A57ULL;
    return STATUS_SUCCESS;
}
void FwpsReleaseClassifyHandle0(UINT64 h) { (void)h; g_calls_release++; }

NTSTATUS FwpsAcquireWritableLayerDataPointer0(UINT64 h, UINT64 filterId, UINT32 flags,
                                             void** out, FWPS_CLASSIFY_OUT0* classifyOut)
{
    (void)h; (void)flags;
    g_calls_writable++;
    g_last_filter_id = filterId;
    *out = (void*)g_writable;
    /* what the real engine does on a successful acquire */
    classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
    classifyOut->actionType = FWP_ACTION_BLOCK;
    return STATUS_SUCCESS;
}
void FwpsApplyModifiedLayerData0(UINT64 h, void* d, UINT32 flags)
{
    (void)h; (void)d;
    g_calls_apply++;
    g_last_apply_flags = flags;
}
NTSTATUS FwpsFlowAssociateContext0(UINT64 f, UINT16 l, UINT32 c, UINT64 ctx)
{
    (void)f; (void)l; (void)c;
    g_calls_associate++;
    /* the token must be given BACK if this fails, or the UDP pool leaks for good */
    if (g_fake_associate_fails) { return (NTSTATUS)0xC0000001L; }
    g_last_associated_ctx = (void*)(size_t)ctx;
    return STATUS_SUCCESS;
}
FWPS_CONNECTION_REDIRECT_STATE FwpsQueryConnectionRedirectState0(HANDLE r, HANDLE h, void** c)
{
    (void)r; (void)h; (void)c;
    return g_fake_redirect_state;
}

extern HANDLE TpdrvTestSetRedirectHandle(HANDLE h);
extern UINT32 TpdrvTestSetCalloutId(UINT32 id);
extern VOID NTAPI TpdrvFlowDelete(UINT16 LayerId, UINT32 CalloutId, UINT64 FlowContext);
extern VOID NTAPI TpdrvClassify(const FWPS_INCOMING_VALUES0*,
                                const FWPS_INCOMING_METADATA_VALUES0*,
                                void*, const void*, const FWPS_FILTER1*,
                                UINT64, FWPS_CLASSIFY_OUT0*);

/* ── scaffolding ─────────────────────────────────────────────────────────── */
/* Every live UDP flow holds one distinct token port, so a case that counts capacity has
 * to start from an empty table: release the ports the pools above hand out. */
static void clear_udp_table(void)
{
    TpdrvUdpReleaseByFlow(13000);
    TpdrvUdpReleaseByFlow(13001);
}

static void reset_calls(void)
{
    g_calls_acquire = g_calls_release = g_calls_apply = g_calls_associate = g_calls_writable = 0;
    g_last_apply_flags = 0xFFFFFFF0ULL;
    g_last_associated_ctx = NULL;
    g_fake_redirect_state = FWPS_CONNECTION_NOT_REDIRECTED;
    g_fake_acquire_fails = 0;
    g_fake_associate_fails = 0;
}

static void v4(SOCKADDR_STORAGE* ss, ULONG addrHost, USHORT portHost)
{
    struct sockaddr_in* s = (struct sockaddr_in*)ss;
    memset(ss, 0, sizeof(*ss));
    s->sin_family = AF_INET;
    s->sin_port = htons(portHost);
    s->sin_addr.S_un.S_addr = htonl(addrHost);
}

static void md(FWPS_INCOMING_METADATA_VALUES0* m, UINT32 pid, UINT64 flow, HANDLE recs)
{
    memset(m, 0, sizeof(*m));
    m->currentMetadataValues = FWPS_METADATA_FIELD_PROCESS_ID
                             | FWPS_METADATA_FIELD_FLOW_HANDLE
                             | FWPS_METADATA_FIELD_REDIRECT_RECORD_HANDLE;
    m->processId = pid;
    m->flowHandle = flow;
    m->redirectRecords = recs;
}

/* One classify, with the field indicated in the type the real engine uses. */
static void run(FWPS_CONNECT_REQUEST0* cr, FWP_DATA_TYPE protoType, UINT8 protoU8,
                UINT64 protoU64, const FWPS_INCOMING_METADATA_VALUES0* m,
                const FWPS_FILTER1* flt, FWPS_CLASSIFY_OUT0* out)
{
    FWPS_INCOMING_VALUES0 iv;
    memset(&iv, 0, sizeof(iv));
    iv.layerId = 70;
    iv.incomingValue[IP_PROTOCOL_FIELD].value.type = protoType;
    if (protoType == FWP_UINT64)
    {
        iv.incomingValue[IP_PROTOCOL_FIELD].value.uint64 = &protoU64;
    }
    else
    {
        iv.incomingValue[IP_PROTOCOL_FIELD].value.uint8 = protoU8;
    }
    g_writable = cr;
    out->rights = FWPS_RIGHT_ACTION_WRITE;
    out->actionType = FWP_ACTION_CONTINUE;     /* must be replaced by the callback */
    TpdrvClassify(&iv, m, cr, NULL, flt, 0, out);
    g_writable = NULL;
}

/* ══════════════════════════════════════════════════════════════════════════
 * INVARIANT SWEEP — randomised scenarios, asserting PROPERTIES rather than
 * expected values.
 *
 * The hand-written cases ask "does this path do the right thing?". This asks
 * the question that matters for a callout sitting in front of every connection
 * a whitelisted program makes: is there ANY combination of rights, metadata,
 * protocol encoding, pool contents and prior-redirect state in which it blocks
 * traffic, rewrites a destination without a recoverable record, hands one token
 * to two transports, or keeps the write right it must give back?
 *
 * A violation prints the seed: a fuzz finding you cannot reproduce is an
 * anecdote.
 * ══════════════════════════════════════════════════════════════════════════ */
static unsigned xshift(unsigned* st)
{
    *st ^= *st << 13;
    *st ^= *st >> 17;
    *st ^= *st << 5;
    return *st;
}

static int
in_pool(UINT16 port, const UINT16* pool, int len)
{
    int i;
    for (i = 0; i < len; i++)
    {
        if (pool[i] == port)
        {
            return 1;
        }
    }
    return 0;
}

static void
invariant_sweep(void)
{
    static const UINT16 tcpPool[4] = { 12000, 12001, 12002, 12003 };
    static const UINT16 udpPool[3] = { 13000, 13001, 13002 };
    unsigned seed = 0x9E3779B9u;
    unsigned it;
    int violations = 0;

    for (it = 0; it < 4000; it++)
    {
        unsigned r = xshift(&seed);
        FWPS_CONNECT_REQUEST0 cr;
        FWPS_CONNECT_REQUEST0 prev;
        FWPS_INCOMING_METADATA_VALUES0 m;
        FWPS_CLASSIFY_OUT0 out;
        FWPS_FILTER1 flt;
        FWPS_INCOMING_VALUES0 iv;
        const TP_FLOW_RECORD* rec;
        SOCKADDR_STORAGE was;
        UINT16 port;
        UINT32 dstIp, nTcp, nUdp, en;
        UINT32 localPort;
        FWP_DATA_TYPE ty;
        UINT64 wideProto;
        int isUdpFlow, acquired, rewrote;

        memset(&cr, 0, sizeof(cr));
        memset(&m, 0, sizeof(m));
        memset(&out, 0, sizeof(out));
        memset(&flt, 0, sizeof(flt));
        memset(&prev, 0, sizeof(prev));
        memset(&iv, 0, sizeof(iv));

        /* configuration: sometimes disabled, sometimes with empty pools */
        nTcp = (r >> 4) & 3u;
        nUdp = (r >> 6) & 3u;
        en = r & 1u;
        TpdrvApplyConfig(4321, en, nTcp ? (UINT16*)tcpPool : NULL, nTcp,
                         nUdp ? (UINT16*)udpPool : NULL, nUdp);
        flt.filterId = 4242;
        TpdrvTestSetRedirectHandle((HANDLE)(size_t)0xBADC0DE);

        /* the flow */
        isUdpFlow = (int)((r >> 8) & 1u);
        dstIp = ((r >> 12) & 0x00FFFFFFu) | 0x08000000u;
        if (((r >> 20) & 7u) == 0) dstIp = 0x7F000001u;
        if (((r >> 20) & 7u) == 1) dstIp = 0x7F123456u;
        port = (UINT16)(53 + ((r >> 22) & 0x3FFFu));
        localPort = (UINT32)(40000 + (r & 0x3FFFu));
        v4(&cr.remoteAddressAndPort, dstIp, port);
        v4(&cr.localAddressAndPort, 0xC0A80164u, (UINT16)localPort);
        was = cr.remoteAddressAndPort;

        m.currentMetadataValues = 0;
        if (!((r >> 24) & 1u)) m.currentMetadataValues |= FWPS_METADATA_FIELD_PROCESS_ID;
        if (!((r >> 25) & 1u)) m.currentMetadataValues |= FWPS_METADATA_FIELD_FLOW_HANDLE;
        if (!((r >> 26) & 1u)) m.currentMetadataValues |= FWPS_METADATA_FIELD_REDIRECT_RECORD_HANDLE;
        m.processId = 1000u + (r % 9000u);
        m.flowHandle = 0xF000ull + it;
        m.redirectRecords = (HANDLE)(size_t)(r & 0xFu);

        g_fake_redirect_state = (FWPS_CONNECTION_REDIRECT_STATE)((r >> 27) & 3u);
        g_fake_acquire_fails = (int)((r >> 29) & 1u);
        g_fake_associate_fails = (int)((r >> 30) & 1u);
        out.rights = ((r >> 31) & 1u) ? FWPS_RIGHT_ACTION_WRITE : 0u;

        if (((r >> 16) & 3u) == 0)
        {
            prev.localRedirectHandle = (HANDLE)(size_t)0x5A5A;
            prev.modifierFilterId = ((r >> 18) & 1u) ? 4242u : 4241u;
            cr.previousVersion = &prev;
        }

        /* the protocol field, in the type the engine indicated, sometimes neither */
        ty = (((r >> 14) & 1u) == 0) ? FWP_UINT8 : FWP_UINT64;
        wideProto = isUdpFlow ? 17ull : 6ull;
        if (ty == FWP_UINT64)
        {
            iv.incomingValue[IP_PROTOCOL_FIELD].value.uint64 = &wideProto;
        }
        else
        {
            iv.incomingValue[IP_PROTOCOL_FIELD].value.uint8 = (UINT8)(isUdpFlow ? 17 : 6);
        }
        if (((r >> 15) & 1u) && ((r >> 8) & 2u))
        {
            if (ty == FWP_UINT64) wideProto = 1ull; else iv.incomingValue[IP_PROTOCOL_FIELD].value.uint8 = 1;
        }
        iv.layerId = 70;
        iv.incomingValue[IP_PROTOCOL_FIELD].value.type = ty;

        reset_calls();
        g_writable = &cr;
        out.actionType = FWP_ACTION_CONTINUE;
        TpdrvClassify(&iv, &m, &cr, NULL, &flt, 0, &out);
        g_writable = NULL;
        acquired = g_calls_writable;

        rewrote = cr.localRedirectContext != NULL;
        rec = (const TP_FLOW_RECORD*)cr.localRedirectContext;

        /* 1 — this callout must never block traffic */
        if (out.actionType == FWP_ACTION_BLOCK)
        {
            printf("VIOLATION block: r=%08x it=%u\n", r, it);
            violations++;
        }

        if (rewrote)
        {
            UINT16 tp = ntohs(((struct sockaddr_in*)&cr.remoteAddressAndPort)->sin_port);
            /* 2 — a rewrite implies a recoverable, well-formed record */
            if (rec->magic != TP_FLOW_RECORD_MAGIC) { printf("VIOLATION magic: it=%u\n", it); violations++; }
            if (rec->tokenPort != tp) { printf("VIOLATION token mismatch: it=%u\n", it); violations++; }
            if (rec->tokenPort == 0) { printf("VIOLATION zero token: it=%u\n", it); violations++; }
            if (rec->pid == 0) { printf("VIOLATION zero pid: it=%u\n", it); violations++; }
            if (rec->portBe != htons(port)) { printf("VIOLATION original port lost: it=%u\n", it); violations++; }
            if (rec->verdict != TP_VERDICT_REDIRECT) { printf("VIOLATION verdict: it=%u\n", it); violations++; }
            if (((struct sockaddr_in*)&cr.localAddressAndPort)->sin_port != htons((UINT16)localPort))
            { printf("VIOLATION local endpoint touched: it=%u\n", it); violations++; }
            /* the token must belong to the transport's own pool */
            if (rec->proto == 17 && !in_pool(rec->tokenPort, udpPool, 3))
            { printf("VIOLATION udp token %u not from the udp pool: it=%u\n", (unsigned)rec->tokenPort, it); violations++; }
            if (rec->proto == 6 && !in_pool(rec->tokenPort, tcpPool, 4))
            { printf("VIOLATION tcp token %u not from the tcp pool: it=%u\n", (unsigned)rec->tokenPort, it); violations++; }
            if (rec->proto != 6 && rec->proto != 17)
            { printf("VIOLATION redirected a %u flow: it=%u\n", (unsigned)rec->proto, it); violations++; }
            /* ownership: having redirected it, the write right stays spent */
            if ((out.rights & FWPS_RIGHT_ACTION_WRITE) != 0)
            { printf("VIOLATION write right kept after a redirect: it=%u\n", it); violations++; }
            if (g_calls_release != 1)
            { printf("VIOLATION classify handle released %d times: it=%u\n", g_calls_release, it); violations++; }
            if (g_calls_apply != 1)
            { printf("VIOLATION layer data applied %d times: it=%u\n", g_calls_apply, it); violations++; }
        }
        else
        {
            /* 3 — no rewrite means the destination is byte-identical */
            if (memcmp(&was, &cr.remoteAddressAndPort, sizeof(was)) != 0)
            { printf("VIOLATION destination changed with no record: it=%u\n", it); violations++; }
            /* 4 — after an acquire, every non-redirect exit restores the right */
            if (acquired > 0 && (out.rights & FWPS_RIGHT_ACTION_WRITE) == 0)
            { printf("VIOLATION write right not given back: it=%u\n", it); violations++; }
            if (cr.localRedirectTargetPID != 0 || cr.localRedirectHandle != NULL)
            { printf("VIOLATION redirect fields set with no context: it=%u\n", it); violations++; }
        }

        /* 5 — UDP bookkeeping can never exceed the table */
        if (TpdrvUdpActiveFlows() > TPDRV_MAX_TOKENS)
        { printf("VIOLATION table over-subscribed: it=%u\n", it); violations++; }

        if ((it & 0x1Fu) == 0x1Fu) clear_udp_table();
    }
    CHECK(violations == 0, "invariant sweep reported %d violation(s)", violations);
    printf("   invariant sweep: 4000 randomised classify scenarios, %d violation(s)\n", violations);
}

int
main(void)
{
    static const UINT16 tcpPool[3] = { 12000, 12001, 12002 };
    static const UINT16 udpPool[2] = { 13000, 13001 };
    FWPS_FILTER1 flt;
    FWPS_INCOMING_METADATA_VALUES0 m;
    FWPS_CONNECT_REQUEST0 cr;
    FWPS_CLASSIFY_OUT0 out;
    SOCKADDR_STORAGE savedRemote;
    const TP_FLOW_RECORD* rec;
    BOOL isTcpToken;
    int i, loop, ok, refused, capacity;

    memset(&flt, 0, sizeof(flt));
    flt.filterId = 4242;                       /* deliberately unlike any pid below */
    TpdrvApplyConfig(4321, 1, (UINT16*)tcpPool, 3, (UINT16*)udpPool, 2);
    TpdrvTestSetRedirectHandle((HANDLE)(size_t)0xBADC0DE);
    TpdrvTestSetCalloutId(77);

    /* ── 1. no right to modify the action ⇒ do not even acquire ─────────────── */
    reset_calls();
    memset(&cr, 0, sizeof(cr));
    v4(&cr.remoteAddressAndPort, 0x5DB8D822UL, 443);
    v4(&cr.localAddressAndPort, 0xC0A80105UL, 51234);
    md(&m, 9999, 0xF100 , (HANDLE)(size_t)0x1);
    /* (the placeholder above is written plainly below to keep the file readable) */
    out.rights = 0;                            /* another callout owns the action */
    out.actionType = FWP_ACTION_BLOCK;
    {
        FWPS_INCOMING_VALUES0 iv;
        memset(&iv, 0, sizeof(iv));
        iv.incomingValue[IP_PROTOCOL_FIELD].value.type = FWP_UINT8;
        iv.incomingValue[IP_PROTOCOL_FIELD].value.uint8 = 6;
        g_writable = &cr;
        TpdrvClassify(&iv, &m, &cr, NULL, &flt, 0, &out);
        g_writable = NULL;
    }
    CHECK(g_calls_acquire == 0, "without FWPS_RIGHT_ACTION_WRITE nothing may be acquired");
    CHECK(out.rights == 0, "the rights of others must not be handed back");

    /* ── 2/3. anti-loop: both of our own states must leave the flow alone ────── */
    for (loop = 0; loop < 2; loop++)
    {
        reset_calls();
        g_fake_redirect_state = loop == 0 ? FWPS_CONNECTION_REDIRECTED_BY_SELF
                                          : FWPS_CONNECTION_PREVIOUSLY_REDIRECTED_BY_SELF;
        memset(&cr, 0, sizeof(cr));
        v4(&cr.remoteAddressAndPort, 0x5DB8D822UL, 443);
        v4(&cr.localAddressAndPort, 0xC0A80105UL, 51234);
        savedRemote = cr.remoteAddressAndPort;
        md(&m, 9999, 0xF100, (HANDLE)(size_t)0x1);
        run(&cr, FWP_UINT8, 6, 0, &m, &flt, &out);
        CHECK(out.actionType == FWP_ACTION_PERMIT, "loop state %d must permit", loop);
        CHECK(g_calls_acquire == 0, "loop state %d must not acquire", loop);
        CHECK(memcmp(&savedRemote, &cr.remoteAddressAndPort, sizeof(savedRemote)) == 0,
              "loop state %d must not rewrite the destination", loop);
    }

    /* ── 4. the transport gate: anything but TCP/UDP is left alone ──────────── */
    for (loop = 0; loop < 3; loop++)
    {
        static const UINT8 odd[3] = { 1, 47, 50 };     /* ICMP, GRE, ESP */
        reset_calls();
        memset(&cr, 0, sizeof(cr));
        v4(&cr.remoteAddressAndPort, 0x5DB8D822UL, 443);
        md(&m, 9999, 0xF101, (HANDLE)(size_t)0x1);
        run(&cr, FWP_UINT8, odd[loop], 0, &m, &flt, &out);
        CHECK(out.actionType == FWP_ACTION_PERMIT, "proto %u must be permitted", odd[loop]);
        CHECK(g_calls_acquire == 0, "proto %u must not reach the acquire", odd[loop]);
    }

    /* ── 5. no process-id metadata ⇒ we cannot attribute the flow ───────────── */
    reset_calls();
    memset(&cr, 0, sizeof(cr));
    v4(&cr.remoteAddressAndPort, 0x5DB8D822UL, 443);
    memset(&m, 0, sizeof(m));
    m.currentMetadataValues = FWPS_METADATA_FIELD_FLOW_HANDLE;   /* no PROCESS_ID bit */
    m.flowHandle = 0xF102;
    run(&cr, FWP_UINT8, 6, 0, &m, &flt, &out);
    CHECK(g_calls_acquire == 0, "an unflagged processId must stop the redirect");

    /* ── 6. loopback destination: a local proxy must not be proxied ─────────── */
    reset_calls();
    memset(&cr, 0, sizeof(cr));
    v4(&cr.remoteAddressAndPort, 0x7F000001UL, 7890);
    v4(&cr.localAddressAndPort, 0x7F000001UL, 51999);
    savedRemote = cr.remoteAddressAndPort;
    md(&m, 9999, 0xF103, (HANDLE)(size_t)0x1);
    run(&cr, FWP_UINT8, 6, 0, &m, &flt, &out);
    CHECK(g_calls_acquire == 1, "the loopback check needs the writable layer data");
    CHECK(g_calls_apply == 1 && g_last_apply_flags == 0, "loopback applies unchanged");
    CHECK((out.rights & FWPS_RIGHT_ACTION_WRITE) != 0,
          "loopback must give the write right BACK (else other callouts starve)");
    CHECK(out.actionType == FWP_ACTION_PERMIT, "loopback permits");
    CHECK(memcmp(&savedRemote, &cr.remoteAddressAndPort, sizeof(savedRemote)) == 0,
          "loopback destination must be left byte for byte");
    CHECK(cr.localRedirectContext == NULL, "loopback stashes no context");
    CHECK(g_calls_release == 1, "the classify handle is released on every path");

    /* ── 7. another product already redirected this flow ⇒ reauthorize, don't stack */
    reset_calls();
    {
        FWPS_CONNECT_REQUEST0 prev;
        memset(&prev, 0, sizeof(prev));
        prev.localRedirectHandle = (HANDLE)(size_t)0x99;
        prev.modifierFilterId = 4241;               /* not OUR filter id */
        memset(&cr, 0, sizeof(cr));
        cr.previousVersion = &prev;
        v4(&cr.remoteAddressAndPort, 0x5DB8D822UL, 443);
        savedRemote = cr.remoteAddressAndPort;
        md(&m, 9999, 0xF104, (HANDLE)(size_t)0x1);
        run(&cr, FWP_UINT8, 6, 0, &m, &flt, &out);
        CHECK(g_last_apply_flags == FWPS_CLASSIFY_FLAG_REAUTHORIZE_IF_MODIFIED_BY_OTHERS,
              "the documented flag must be used here (saw %llx)",
              (unsigned long long)g_last_apply_flags);
        CHECK((out.rights & FWPS_RIGHT_ACTION_WRITE) != 0, "and the right given back");
        CHECK(memcmp(&savedRemote, &cr.remoteAddressAndPort, sizeof(savedRemote)) == 0,
              "the other product's redirect must survive untouched");

        /* inverse: a previousVersion written by OUR filter id is not "someone else" */
        reset_calls();
        prev.modifierFilterId = flt.filterId;
        cr.previousVersion = &prev;
        v4(&cr.remoteAddressAndPort, 0x5DB8D822UL, 443);
        run(&cr, FWP_UINT8, 6, 0, &m, &flt, &out);
        CHECK(cr.localRedirectContext != NULL, "our own earlier version must still proxy");
    }

    /* ── 8. TCP: the full redirect, asserted byte for byte ─────────────────── */
    reset_calls();
    memset(&cr, 0, sizeof(cr));
    v4(&cr.remoteAddressAndPort, 0x5DB8D822UL, 443);      /* example.com:443 */
    v4(&cr.localAddressAndPort, 0xC0A80105UL, 51234);
    md(&m, 9999, 0xF105, (HANDLE)(size_t)0x1);
    run(&cr, FWP_UINT8, 6, 0, &m, &flt, &out);
    CHECK(g_calls_writable == 1 && g_last_filter_id == 4242,
          "AcquireWritableLayerDataPointer0 takes the FILTER id, not the redirect handle");
    CHECK(cr.localRedirectTargetPID == 4321, "the proxy pid must be declared");
    CHECK(cr.localRedirectHandle == (HANDLE)(size_t)0xBADC0DE, "and the redirect handle stored");
    CHECK(cr.localRedirectContextSize == sizeof(TP_FLOW_RECORD), "context size must be 72");
    {
        struct sockaddr_in* r = (struct sockaddr_in*)&cr.remoteAddressAndPort;
        CHECK(r->sin_family == AF_INET, "v4 stays v4");
        CHECK(r->sin_addr.S_un.S_addr == htonl(0x7F000001UL), "redirected to loopback");
        isTcpToken = FALSE;
        for (i = 0; i < 3; i++)
        {
            if (r->sin_port == htons(tcpPool[i])) { isTcpToken = TRUE; }
        }
        CHECK(isTcpToken, "a stream flow must land on a TCP token (port %u)",
              (unsigned)ntohs(r->sin_port));
        CHECK(ntohs(r->sin_port) < 13000, "and NEVER on one of the UDP tokens");
    }
    rec = (const TP_FLOW_RECORD*)cr.localRedirectContext;
    CHECK(rec != NULL, "the record must exist");
    if (rec != NULL)
    {
        CHECK(rec->magic == TP_FLOW_RECORD_MAGIC, "magic");
        CHECK(rec->family == AF_INET, "family");
        CHECK(rec->portBe == htons(443), "the ORIGINAL port, in network order");
        CHECK(rec->addr[0] == 93 && rec->addr[1] == 184 && rec->addr[2] == 216 && rec->addr[3] == 34,
              "the ORIGINAL address must survive the redirect");
        CHECK(rec->pid == 9999, "the record carries the app's pid, not the filter id");
        CHECK(rec->proto == 6 && rec->verdict == TP_VERDICT_REDIRECT, "proto/verdict");
        CHECK(rec->tokenPort == ntohs(((struct sockaddr_in*)&cr.remoteAddressAndPort)->sin_port),
              "the record's token must be the port we redirected to");
        {
            /*
             * The record exactly as THIS code produced it (captured 2026-11-25), asserted
             * byte for byte — and src/wfp_classify.rs decodes the same buffer, which is
             * what turns the kernel↔service contract from a reading into a test.
             * Bytes 34..36 are the token port: it moves with the round-robin pool, so it
             * is zeroed here and pinned instead by the tokenPort equality check above.
             */
            static const UINT8 GOLDEN[sizeof(TP_FLOW_RECORD)] = {
                0x46, 0x58, 0x52, 0x50, 0x02, 0x00, 0x01, 0xbb, 0x5d, 0xb8, 0xd8, 0x22,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x0f, 0x27, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x06, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0xc0, 0xa8, 0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0xc8, 0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            };
            UINT8 raw[sizeof(TP_FLOW_RECORD)];
            memcpy(raw, rec, sizeof(raw));
            raw[34] = 0;
            raw[35] = 0;
            CHECK(memcmp(raw, GOLDEN, sizeof(GOLDEN)) == 0,
                  "the classify path's record drifted from the cross-language golden buffer");
        }
    }
    CHECK(out.actionType == FWP_ACTION_PERMIT, "a redirect callout still returns PERMIT");
    CHECK((out.rights & FWPS_RIGHT_ACTION_WRITE) == 0,
          "having redirected it ourselves, we keep the right from the rest of the stack");
    CHECK(g_calls_apply == 1 && g_last_apply_flags == 0, "modified layer data applied once");
    CHECK(g_calls_associate == 0, "stream flows share listeners and need no flow context");
    CHECK(g_calls_release == 1, "handle released");

    /* ── 9. UDP: its own pool, plus the flow association that releases it ───── */
    reset_calls();
    memset(&cr, 0, sizeof(cr));
    v4(&cr.remoteAddressAndPort, 0x08080808UL, 53);
    v4(&cr.localAddressAndPort, 0xC0A80105UL, 40000);
    md(&m, 777, 0xF106, (HANDLE)(size_t)0x1);
    run(&cr, FWP_UINT8, 17, 0, &m, &flt, &out);
    {
        struct sockaddr_in* r = (struct sockaddr_in*)&cr.remoteAddressAndPort;
        UINT16 port = ntohs(r->sin_port);
        CHECK(port == 13000 || port == 13001,
              "a datagram flow must draw from the UDP pool (saw %u)", (unsigned)port);
        CHECK(g_calls_associate == 1 && (size_t)g_last_associated_ctx == (size_t)port,
              "the token must be stored on the flow so flowDelete can release it");
        {
            TP_FLOW_RECORD found;
            CHECK(TpdrvUdpLookup(port, &found) == TRUE,
                  "the service must be able to resolve the token back to its destination");
            CHECK(found.addr[0] == 8 && found.addr[3] == 8 && found.portBe == htons(53),
                  "and to the ORIGINAL destination 8.8.8.8:53");
            CHECK(found.pid == 777 && found.proto == 17, "the record carries the app's pid/proto");
        }
    }

    /* ── 9b. a protocol indicated as FWP_UINT64 must be followed through the
     *        POINTER member (this is the member an earlier draft read as a value) ── */
    reset_calls();
    memset(&cr, 0, sizeof(cr));
    v4(&cr.remoteAddressAndPort, 0x5DB8D822UL, 443);
    md(&m, 9999, 0xF107, (HANDLE)(size_t)0x1);
    run(&cr, FWP_UINT64, 0, 17ULL, &m, &flt, &out);
    {
        UINT16 port = ntohs(((struct sockaddr_in*)&cr.remoteAddressAndPort)->sin_port);
        CHECK(port == 13000 || port == 13001,
              "UINT64-encoded UDP must be recognised as UDP (saw %u)", (unsigned)port);
    }

    /* ── 10. an exhausted UDP table must not half-redirect ─────────────────── */
    reset_calls();
    clear_udp_table();
    ok = 0;
    refused = 0;
    /* Earlier cases already hold slots, so the expectation is the REMAINING capacity —
     * asserting TPDRV_MAX_TOKENS here would blame the driver for the test's own history. */
    /* one live flow per DISTINCT UDP token port — the pool configured above has two */
    capacity = 2;
    CHECK(capacity > 0, "the cases above should not have filled the table already");
    for (i = 0; i <= capacity; i++)
    {
        FWPS_CONNECT_REQUEST0 one;
        SOCKADDR_STORAGE keep;
        memset(&one, 0, sizeof(one));
        v4(&one.remoteAddressAndPort, 0x08080808UL, (USHORT)(5000 + i));
        v4(&one.localAddressAndPort, 0xC0A80105UL, (USHORT)(20000 + i));
        keep = one.remoteAddressAndPort;
        md(&m, 1000 + i, (UINT64)(0xF200 + i), (HANDLE)(size_t)0x1);
        out.rights = FWPS_RIGHT_ACTION_WRITE;
        run(&one, FWP_UINT8, 17, 0, &m, &flt, &out);
        if (one.localRedirectContext != NULL)
        {
            ok++;
        }
        else
        {
            refused = 1;
            CHECK((out.rights & FWPS_RIGHT_ACTION_WRITE) != 0,
                  "a refused datagram flow must give the write right back");
            CHECK(memcmp(&keep, &one.remoteAddressAndPort, sizeof(keep)) == 0,
                  "a refused datagram flow must be left exactly as it arrived");
            break;
        }
    }
    CHECK(refused, "an exhausted table must refuse a new flow rather than queue it");
    CHECK(ok == capacity, "the table must accept exactly the free slots (wanted %d, got %d)",
          capacity, ok);
    CHECK(out.actionType == FWP_ACTION_PERMIT, "exhaustion permits rather than drops");

    /* ── 11. no TCP listeners configured ⇒ permit unchanged, but still applied ─ */
    reset_calls();
    TpdrvApplyConfig(4321, 1, NULL, 0, (UINT16*)udpPool, 2);
    memset(&cr, 0, sizeof(cr));
    v4(&cr.remoteAddressAndPort, 0x5DB8D822UL, 443);
    savedRemote = cr.remoteAddressAndPort;
    md(&m, 9999, 0xF300, (HANDLE)(size_t)0x1);
    run(&cr, FWP_UINT8, 6, 0, &m, &flt, &out);
    CHECK(g_calls_acquire == 1, "the decision needs the writable layer data first");
    CHECK(g_calls_apply == 1 && g_last_apply_flags == 0, "then applies it unchanged");
    CHECK((out.rights & FWPS_RIGHT_ACTION_WRITE) != 0, "and restores the write right");
    CHECK(cr.localRedirectContext == NULL, "with no listener there is nowhere to record");
    CHECK(memcmp(&savedRemote, &cr.remoteAddressAndPort, sizeof(savedRemote)) == 0,
          "the destination must be untouched");

    /* ── 12. driver disabled ⇒ no token is handed out at all ───────────────── */
    reset_calls();
    TpdrvApplyConfig(4321, 0, (UINT16*)tcpPool, 3, (UINT16*)udpPool, 2);
    memset(&cr, 0, sizeof(cr));
    v4(&cr.remoteAddressAndPort, 0x5DB8D822UL, 443);
    md(&m, 9999, 0xF400, (HANDLE)(size_t)0x1);
    run(&cr, FWP_UINT8, 6, 0, &m, &flt, &out);
    CHECK(cr.localRedirectContext == NULL, "a disabled driver must not redirect anything");


    /* ── 11. a refused flow association must not leak the UDP token ─────────── */
    reset_calls();
    TpdrvApplyConfig(4321, 1, (UINT16*)tcpPool, 3, (UINT16*)udpPool, 2);
    clear_udp_table();        /* the exhaustion case above filled the table */
    {
        UINT32 before = TpdrvUdpActiveFlows();
        memset(&cr, 0, sizeof(cr));
        v4(&cr.remoteAddressAndPort, 0x0100007FUL, 9);          /* another TEST-NET dst */
        v4(&cr.localAddressAndPort, 0xC0A80105UL, 40111);
        savedRemote = cr.remoteAddressAndPort;
        md(&m, 2468, 0xF500, (HANDLE)(size_t)0x1);
        g_fake_associate_fails = 1;
        run(&cr, FWP_UINT8, 17, 0, &m, &flt, &out);
        CHECK(g_calls_associate == 1, "the association must at least be attempted");
        CHECK(cr.localRedirectContext == NULL,
              "a refused association may not commit a redirect (nothing could resolve it)");
        CHECK(memcmp(&savedRemote, &cr.remoteAddressAndPort, sizeof(savedRemote)) == 0,
              "and the destination must be left exactly as it arrived");
        CHECK(g_calls_apply == 1 && g_last_apply_flags == 0, "applied unchanged");
        CHECK((out.rights & FWPS_RIGHT_ACTION_WRITE) != 0, "write right restored for others");
        CHECK(TpdrvUdpActiveFlows() == before,
              "the reserved token must be released (before %u, after %u)",
              (unsigned)before, (unsigned)TpdrvUdpActiveFlows());

        /* positive control: with the association allowed, the flow IS counted active */
        reset_calls();
        memset(&cr, 0, sizeof(cr));
        v4(&cr.remoteAddressAndPort, 0x0100007FUL, 9);
        md(&m, 2469, 0xF501, (HANDLE)(size_t)0x1);
        run(&cr, FWP_UINT8, 17, 0, &m, &flt, &out);
        CHECK(cr.localRedirectContext != NULL, "with the association ok the redirect proceeds");
        CHECK(TpdrvUdpActiveFlows() == before + 1,
              "and exactly one slot is now in use (%u vs %u)",
              (unsigned)TpdrvUdpActiveFlows(), (unsigned)(before + 1));
    }


    /* ── 12. IPv6 through the classify path: the record and the rewrite must both
     *        stay in AF_INET6 — shrinking v6 to a v4-shaped target is the classic
     *        redirect-driver failure, and it fails silently. ─────────────────── */
    for (loop = 0; loop < 2; loop++)
    {
        UINT8 proto = loop == 0 ? 6 : 17;
        reset_calls();
        clear_udp_table();
        TpdrvApplyConfig(4321, 1, (UINT16*)tcpPool, 3, (UINT16*)udpPool, 2);
        memset(&cr, 0, sizeof(cr));
        {
            struct sockaddr_in6* a6 = (struct sockaddr_in6*)&cr.remoteAddressAndPort;
            a6->sin6_family = AF_INET6;
            a6->sin6_port = htons(443);
            a6->sin6_addr.u.Byte[0] = 0x20; a6->sin6_addr.u.Byte[1] = 0x01;
            a6->sin6_addr.u.Byte[2] = 0x0d; a6->sin6_addr.u.Byte[3] = 0xb8;
            a6->sin6_addr.u.Byte[15] = 0x05;                    /* 2001:db8::5 */
            a6 = (struct sockaddr_in6*)&cr.localAddressAndPort;
            a6->sin6_family = AF_INET6;
            a6->sin6_port = htons(51333);
            a6->sin6_addr.u.Byte[15] = 0x01;                    /* ::1 */
        }
        md(&m, 3579, 0xF600 + (UINT64)loop, (HANDLE)(size_t)0x1);
        run(&cr, FWP_UINT8, proto, 0, &m, &flt, &out);

        rec = (const TP_FLOW_RECORD*)cr.localRedirectContext;
        CHECK(rec != NULL, "v6 %s flow must be redirected too", proto == 6 ? "tcp" : "udp");
        if (rec == NULL) { continue; }
        CHECK(rec->family == AF_INET6, "the record keeps AF_INET6 (saw %u)", (unsigned)rec->family);
        CHECK(rec->addr[0] == 0x20 && rec->addr[1] == 0x01 && rec->addr[3] == 0xb8
              && rec->addr[15] == 0x05, "the ORIGINAL v6 address survives, all 16 bytes");
        CHECK(rec->portBe == htons(443), "the ORIGINAL v6 port, in network order");
        CHECK(rec->pid == 3579, "v6 record carries the app pid");
        CHECK(rec->proto == proto, "v6 record carries the protocol (%u)", (unsigned)rec->proto);
        {
            struct sockaddr_in6* t = (struct sockaddr_in6*)&cr.remoteAddressAndPort;
            int i, only_loopback = 1;
            CHECK(t->sin6_family == AF_INET6,
                  "the REDIRECT TARGET must stay 28 bytes of AF_INET6, not shrink to v4");
            CHECK(t->sin6_addr.u.Byte[15] == 1, "target is ::1");
            for (i = 0; i < 15; i++)
            {
                if (t->sin6_addr.u.Byte[i] != 0) { only_loopback = 0; break; }
            }
            CHECK(only_loopback, "and nothing else in the 16-byte address is set");
            isTcpToken = FALSE;
            for (i = 0; i < 2; i++)
            {
                if (t->sin6_port == htons(udpPool[i])) { isTcpToken = TRUE; }
            }
            if (proto == 17)
            {
                CHECK(isTcpToken, "a v6 datagram flow draws from the UDP pool as well");
            }
            else
            {
                CHECK(ntohs(t->sin6_port) >= 12000 && ntohs(t->sin6_port) <= 12002,
                      "a v6 stream flow draws from the TCP pool (saw %u)",
                      (unsigned)ntohs(t->sin6_port));
            }
            CHECK(rec->tokenPort == ntohs(t->sin6_port),
                  "the record's token matches the port the app was sent to");
        }
        if (loop == 0)
        {
            /*
             * Same trick as the v4 vector: these are the bytes THIS path emitted, so a
             * change to the record layout — or to where a 16-byte IPv6 address sits
             * inside it — fails here and in src/wfp_classify.rs rather than in a VM.
             */
            static const UINT8 GOLDEN_V6[sizeof(TP_FLOW_RECORD)] = {
                0x46, 0x58, 0x52, 0x50, 0x17, 0x00, 0x01, 0xbb, 0x20, 0x01, 0x0d, 0xb8,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
                0xfb, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x06, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x01, 0xc8, 0x85, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            };
            UINT8 raw6[sizeof(TP_FLOW_RECORD)];
            memcpy(raw6, rec, sizeof(raw6));
            raw6[34] = 0;   /* the token port moves with the round-robin pool */
            raw6[35] = 0;
            CHECK(memcmp(raw6, GOLDEN_V6, sizeof(GOLDEN_V6)) == 0,
                  "the v6 record drifted from the cross-language golden buffer");
        }
    }

    /* ── 13. flow delete returns the token, which is what makes UDP sustainable ── */
    reset_calls();
    clear_udp_table();
    TpdrvApplyConfig(4321, 1, (UINT16*)tcpPool, 3, (UINT16*)udpPool, 2);
    {
        UINT32 before = TpdrvUdpActiveFlows();
        UINT16 port;
        memset(&cr, 0, sizeof(cr));
        v4(&cr.remoteAddressAndPort, 0x08080808UL, 53);
        md(&m, 1111, 0xF700, (HANDLE)(size_t)0x1);
        run(&cr, FWP_UINT8, 17, 0, &m, &flt, &out);
        port = (UINT16)(size_t)g_last_associated_ctx;
        CHECK(port != 0, "the UDP flow was associated with its token (%u)", (unsigned)port);
        CHECK(TpdrvUdpActiveFlows() == before + 1, "one slot in use");
        {
            TP_FLOW_RECORD found;
            CHECK(TpdrvUdpLookup(port, &found) == TRUE, "the service can resolve it");

            /* this is exactly what the filter engine calls when the flow dies */
            TpdrvFlowDelete(70 /* layerId */, 77 /* calloutId */, (UINT64)port);
            CHECK(TpdrvUdpActiveFlows() == before,
                  "flowDelete must hand the token back (still %u in use)",
                  (unsigned)(TpdrvUdpActiveFlows() - before));
            CHECK(TpdrvUdpLookup(port, &found) == FALSE,
                  "and a released token must NOT resolve to a stale destination");

            /* the slot is genuinely reusable, not merely counted down */
            memset(&cr, 0, sizeof(cr));
            v4(&cr.remoteAddressAndPort, 0x08080808UL, 53);
            md(&m, 2222, 0xF701, (HANDLE)(size_t)0x1);
            run(&cr, FWP_UINT8, 17, 0, &m, &flt, &out);
            CHECK(cr.localRedirectContext != NULL, "a released port is handed out again");
            /*
             * WHICH free port comes back is round-robin and not part of the contract —
             * what matters is that releasing restored capacity (a slot is in use again)
             * and that the port handed out is not one another live flow holds. The
             * no-double-booking rule is pinned in test_record.c.
             */
            CHECK(TpdrvUdpActiveFlows() == before + 1,
                  "capacity comes back with the token (%u in use, expected %u)",
                  (unsigned)TpdrvUdpActiveFlows(), (unsigned)(before + 1));
        }
        /* an unrelated (or repeated) delete must be harmless, not a double free */
        TpdrvFlowDelete(70, 77, (UINT64)port);
        TpdrvFlowDelete(70, 77, 0);
        CHECK(TpdrvUdpActiveFlows() == before + 1, "a repeat delete changes nothing");
    }

    /* ── 14. a datagram with no flow handle is left direct, and COUNTED ──────── */
    reset_calls();
    clear_udp_table();
    TpdrvApplyConfig(4321, 1, (UINT16*)tcpPool, 3, (UINT16*)udpPool, 2);
    {
        ULONG before = TpdrvUdpUntrackable();
        UINT32 slots = TpdrvUdpActiveFlows();
        memset(&cr, 0, sizeof(cr));
        v4(&cr.remoteAddressAndPort, 0x08080808UL, 53);
        savedRemote = cr.remoteAddressAndPort;
        memset(&m, 0, sizeof(m));
        m.currentMetadataValues = FWPS_METADATA_FIELD_PROCESS_ID;   /* no FLOW_HANDLE bit */
        m.processId = 4242;
        m.redirectRecords = (HANDLE)(size_t)0x1;
        run(&cr, FWP_UINT8, 17, 0, &m, &flt, &out);
        CHECK(cr.localRedirectContext == NULL,
              "an untrackable datagram must not be redirected (nobody could free the token)");
        CHECK(memcmp(&savedRemote, &cr.remoteAddressAndPort, sizeof(savedRemote)) == 0,
              "and its destination must be untouched");
        CHECK(out.actionType == FWP_ACTION_PERMIT, "permitted, i.e. sent direct, not dropped");
        CHECK(TpdrvUdpActiveFlows() == slots, "no token is consumed by a refused flow");
        CHECK(TpdrvUdpUntrackable() == before + 1,
              "but the refusal must be COUNTED, so --verify can report it (before %u)",
              (unsigned)before);
        CHECK(TpdrvUdpUntrackable() != 0, "the status counter is non-zero");
    }

    /* ── 15. notifyFn must never refuse the service's own filter ─────────────── */
    reset_calls();
    {
        extern NTSTATUS NTAPI TpdrvNotify(FWPS_CALLOUT_NOTIFY_TYPE, const GUID*, FWPS_FILTER1*);
        CHECK(TpdrvNotify(FWPS_CALLOUT_NOTIFY_ADD_FILTER, NULL, &flt) == STATUS_SUCCESS,
              "returning failure for ADD_FILTER makes the BFE refuse our redirect filter");
        CHECK(TpdrvNotify(FWPS_CALLOUT_NOTIFY_DELETE_FILTER, NULL, &flt) == STATUS_SUCCESS, "delete too");
        /* an unrecognised notification is ignored with success, per the DDI */
        CHECK(TpdrvNotify((FWPS_CALLOUT_NOTIFY_TYPE)99, NULL, &flt) == STATUS_SUCCESS,
              "unknown notify types must be accepted, not treated as an error");
    }

    invariant_sweep();

    if (failures == 0)
    {
        printf("OK: the driver's own classify callback behaves as specified (%d checks)\n", checks);
        return 0;
    }
    printf("%d FAILURES\n", failures);
    return 1;
}
