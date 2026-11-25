/*
 * test_record.c — runs the driver's encoders on a host compiler.
 *
 *   gcc -I. record.c test_record.c -o test_record && ./test_record
 *
 * Every expectation here is the same literal that trans_proxier::wfp_callout_plan
 * asserts in Rust, so the C that will execute inside the kernel and the Rust that
 * specifies the contract are checked against one another, not merely against
 * somebody's reading of the headers.
 */
#include <stdio.h>
#include <string.h>
#include "record.h"

static int failures = 0;
static int checks = 0;

#define CHECK(cond, ...) do { checks++; if (!(cond)) { printf("FAIL: "); printf(__VA_ARGS__); printf("\n"); failures++; } } while (0)

static const UINT8 EXPECT_V4[] = {0x02,0x00, 0x2A,0x38, 127,0,0,1, 0,0,0,0,0,0,0,0};   /* :10808 */
static const UINT8 EXPECT_V6[] = {0x17,0x00, 0x01,0xBB, 0,0,0,0,
                                  0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,1, 0,0,0,0};          /* [::1]:443 */

int
main(void)
{
    SOCKADDR_STORAGE remote, local, saved;
    TP_FLOW_RECORD r;
    UINT8 *b;
    int i;

    /* ── IPv4: family little-endian, port BIG-endian, 127.0.0.1 ───────────── */
    memset(&remote, 0, sizeof(remote));
    ((struct sockaddr_in*)&remote)->sin_family = AF_INET;
    ((struct sockaddr_in*)&remote)->sin_port = (unsigned short)htons(443);
    ((struct sockaddr_in*)&remote)->sin_addr.S_un.S_addr = htonl(0x5DB8D822UL); /* 93.184.216.34 */
    saved = remote;
    TpdrvSetRedirectTarget(&remote, 10808);
    b = (UINT8*)&remote;
    CHECK(memcmp(b, EXPECT_V4, sizeof(EXPECT_V4)) == 0, "v4 redirect sockaddr bytes");
    CHECK(remote.ss_family == AF_INET, "v4 family preserved");

    /* the ORIGINAL destination must be recoverable for the context */
    memset(&local, 0, sizeof(local));
    ((struct sockaddr_in*)&local)->sin_family = AF_INET;
    ((struct sockaddr_in*)&local)->sin_port = (unsigned short)htons(51234);
    ((struct sockaddr_in*)&local)->sin_addr.S_un.S_addr = htonl(0xC0A80105UL);   /* 192.168.1.5 */
    TpdrvBuildRecord(&r, &saved, &local, 6 /*IPPROTO_TCP*/, 4242, 10808);
    CHECK(r.magic == TP_FLOW_RECORD_MAGIC, "magic");
    CHECK(r.family == AF_INET, "family");
    CHECK(r.portBe == (UINT16)htons(443), "remote port kept in network order");
    CHECK(r.addr[0] == 93 && r.addr[1] == 184 && r.addr[2] == 216 && r.addr[3] == 34, "remote address bytes");
    CHECK(r.localAddr[0] == 192 && r.localAddr[3] == 5, "local address bytes");
    CHECK(r.pid == 4242 && r.proto == 6 && r.tokenPort == 10808, "pid/proto/token");
    CHECK(r.verdict == TP_VERDICT_REDIRECT && r.chain == 0, "verdict + chain left to the service");
    CHECK(((UINT8*)&r)[36] == 0 && ((UINT8*)&r)[39] == 0, "padding stays zero");

    /* the record the Rust side parses: offsets the C_ASSERTs also pin */
    CHECK(*(UINT32*)((UINT8*)&r + 0) == TP_FLOW_RECORD_MAGIC, "magic at 0");
    CHECK(*(UINT16*)((UINT8*)&r + 6) == (UINT16)htons(443), "portBe at 6");
    CHECK(((UINT8*)&r)[32] == TP_VERDICT_REDIRECT, "verdict at 32");
    CHECK(*(UINT16*)((UINT8*)&r + 34) == 10808, "tokenPort at 34");

    /* ── IPv6: must stay 28 bytes of AF_INET6, not shrink to a v4 shape ───── */
    memset(&remote, 0, sizeof(remote));
    ((struct sockaddr_in6*)&remote)->sin6_family = AF_INET6;
    ((struct sockaddr_in6*)&remote)->sin6_port = (unsigned short)htons(53);
    ((struct sockaddr_in6*)&remote)->sin6_addr.u.Byte[0] = 0x20;
    ((struct sockaddr_in6*)&remote)->sin6_addr.u.Byte[1] = 0x01;
    ((struct sockaddr_in6*)&remote)->sin6_addr.u.Byte[2] = 0x0d;
    ((struct sockaddr_in6*)&remote)->sin6_addr.u.Byte[3] = 0xb8;
    ((struct sockaddr_in6*)&remote)->sin6_addr.u.Byte[15] = 0x05;   /* 2001:db8::5 */
    local = remote;
    TpdrvBuildRecord(&r, &remote, &local, 17, 7, 12000);
    CHECK(r.family == AF_INET6, "v6 family recorded");
    CHECK(r.addr[0] == 0x20 && r.addr[3] == 0xb8 && r.addr[15] == 0x05, "v6 address bytes");
    CHECK(r.portBe == (UINT16)htons(53), "v6 port network order");
    TpdrvSetRedirectTarget(&remote, 443);
    b = (UINT8*)&remote;
    CHECK(memcmp(b, EXPECT_V6, sizeof(EXPECT_V6)) == 0, "v6 redirect sockaddr bytes");
    for (i = 0; i < 15; i++)
    {
        if (((struct sockaddr_in6*)&remote)->sin6_addr.u.Byte[i] != 0) { CHECK(0, "v6 target is ::1"); break; }
    }

    /* ── loopback refusal, which is what keeps a local proxy working ───────── */
    memset(&remote, 0, sizeof(remote));
    ((struct sockaddr_in*)&remote)->sin_family = AF_INET;
    ((struct sockaddr_in*)&remote)->sin_addr.S_un.S_addr = htonl(0x7F000001UL);
    CHECK(TpdrvIsLoopbackRemote(&remote) == TRUE, "127.0.0.1 is loopback");
    ((struct sockaddr_in*)&remote)->sin_addr.S_un.S_addr = htonl(0x5DB8D822UL);
    CHECK(TpdrvIsLoopbackRemote(&remote) == FALSE, "93.184.216.34 is not");
    memset(&remote, 0, sizeof(remote));
    ((struct sockaddr_in6*)&remote)->sin6_family = AF_INET6;
    ((struct sockaddr_in6*)&remote)->sin6_addr.u.Byte[15] = 1;
    CHECK(TpdrvIsLoopbackRemote(&remote) == TRUE, "::1 is loopback");
    ((struct sockaddr_in6*)&remote)->sin6_addr.u.Byte[15] = 2;
    CHECK(TpdrvIsLoopbackRemote(&remote) == FALSE, "::2 is not");

    /* ── token pool: disabled or empty must yield 0, never a wild port ────── */
    {
        UINT16 toks[3] = {12000, 12001, 12002};
        UINT16 utoks[2] = {13000, 13001};
        TpdrvApplyConfig(4321, 0, toks, 3, utoks, 2);
        CHECK(TpdrvTakeToken(FALSE) == 0, "disabled driver hands out no token");
        CHECK(TpdrvTakeToken(TRUE) == 0, "disabled driver hands out no udp token");
        TpdrvApplyConfig(4321, 1, NULL, 0, NULL, 0);
        CHECK(TpdrvTakeToken(FALSE) == 0, "empty pool hands out no token");
        TpdrvApplyConfig(4321, 1, toks, 3, utoks, 2);
        {
            UINT16 a = TpdrvTakeToken(FALSE), c = TpdrvTakeToken(FALSE);
            UINT16 d = TpdrvTakeToken(TRUE), e = TpdrvTakeToken(TRUE);
            CHECK(a >= 12000 && a <= 12002 && c >= 12000 && c <= 12002, "tcp tokens come from the tcp pool");
            CHECK((d == 13000 || d == 13001) && (e == 13000 || e == 13001),
                  "udp tokens come from the udp pool — never a tcp listener");
        }
    }

    /* ── the shared golden buffer: same 72 bytes as the Rust test ───────────── */
    {
        static const unsigned char GOLDEN[72] = {
            0x46, 0x58, 0x52, 0x50,  0x02, 0x00, 0x01, 0xBB,
            0xC6, 0x33, 0x64, 0x14,  0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
            0x92, 0x10, 0x00, 0x00,  0x07, 0x00, 0x00, 0x00,
            0x01, 0x06, 0xE0, 0x2E,  0x00, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00,  0xEF, 0xBE, 0xAD, 0xDE,
            0xC0, 0xA8, 0x01, 0x05,  0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
            0x00, 0x50, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00
        };
        TP_FLOW_RECORD rec2;
        memset(&remote, 0, sizeof(remote));
        ((struct sockaddr_in*)&remote)->sin_family = AF_INET;
        ((struct sockaddr_in*)&remote)->sin_port = (unsigned short)htons(443);
        ((struct sockaddr_in*)&remote)->sin_addr.S_un.S_addr = htonl(0xC6336414UL); /* 198.51.100.20 */
        memset(&local, 0, sizeof(local));
        ((struct sockaddr_in*)&local)->sin_family = AF_INET;
        ((struct sockaddr_in*)&local)->sin_port = (unsigned short)htons(80);
        ((struct sockaddr_in*)&local)->sin_addr.S_un.S_addr = htonl(0xC0A80105UL);   /* 192.168.1.5 */
        TpdrvBuildRecord(&rec2, &remote, &local, 6, 4242, 12000);
        /* fields the builder deliberately leaves zero, matched to the Rust input */
        rec2.chain = 7;
        rec2.flowId = 0xDEADBEEF00000001ULL;
        CHECK(memcmp(&rec2, GOLDEN, sizeof(GOLDEN)) == 0,
              "C record bytes differ from the shared golden buffer the service decodes");
        CHECK(rec2.portBe == (UINT16)htons(443), "port octets are the wire order, 01 BB");
    }

    /* ── control-device authorisation: who may arm the redirect target ─────────
     * Without this, any local process that opens the device could point every
     * whitelisted app's traffic at its own loopback ports. */
    CHECK(TpdrvConfigMayBeSetBy(4321, 0) == TRUE, "an unclaimed driver is claimed by its first setter");
    CHECK(TpdrvConfigMayBeSetBy(0, 0) == FALSE, "pid 0 never wins anything");
    CHECK(TpdrvConfigMayBeSetBy(4321, 4321) == TRUE, "the claimant may re-arm");
    CHECK(TpdrvConfigMayBeSetBy(9999, 4321) == FALSE, "a foreign pid may NOT take over an existing claim");
    CHECK(TpdrvConfigMayBeSetBy(9999, 0) == TRUE, "…but it may claim a released driver");
    CHECK(TpdrvMayQueryFlow(4321, 4321) == TRUE, "the claimant may read its own flows");
    CHECK(TpdrvMayQueryFlow(9999, 4321) == FALSE, "nobody else may read another app's destination");
    CHECK(TpdrvMayQueryFlow(4321, 0) == FALSE, "and there is nothing to read before a claim exists");
    {
        /* releasing must clear the claim, or a clean restart would need a driver reload */
        UINT16 toks[1] = { 12999 };
        TpdrvApplyConfig(4321, 1, toks, 1, NULL, 0);
        CHECK(TpdrvProxyPid() == 4321, "enabled: claim held");
        TpdrvApplyConfig(4321, 0, NULL, 0, NULL, 0);
        CHECK(TpdrvProxyPid() == 0, "disabled: claim released for the next instance");
        CHECK(TpdrvConfigMayBeSetBy(7777, TpdrvProxyPid()) == TRUE, "a new pid can arm after disarm");
    }

    /* ── a SHRUNK pool may never hand out a port from the previous, larger one ────
     * classifyFn reads these pools lock-free at DISPATCH_LEVEL, so the writer makes a
     * torn read harmless instead of preventing one: tail zeroed, contents copied, count
     * published last through InterlockedExchange. The observable consequence is this. */
    {
        UINT16 big[4] = { 12000, 12001, 12002, 12003 };
        UINT16 small[1] = { 12000 };
        int k;
        TpdrvApplyConfig(4321, 1, big, 4, NULL, 0);
        for (k = 0; k < 6; k++)
        {
            (void)TpdrvTakeToken(FALSE);          /* move the round-robin cursor on */
        }
        TpdrvApplyConfig(4321, 1, small, 1, NULL, 0);
        for (k = 0; k < 6; k++)
        {
            UINT16 t = TpdrvTakeToken(FALSE);
            CHECK(t == 12000,
                  "after shrinking to one port the driver must never return a stale "
                  "entry (saw %u)", (unsigned)t);
        }
        /* and zeroing the count leaves nothing to hand out at all */
        TpdrvApplyConfig(4321, 1, NULL, 0, NULL, 0);
        CHECK(TpdrvTakeToken(FALSE) == 0, "a cleared pool yields no token");
    }

    /* ── input validation: the buffer must contain what the counts claim ───────
     * The missing UDP bound was a kernel pool over-read whose result became routing
     * state, so the exact request shape that triggered it stays pinned here. */
    {
        /* derived from the struct itself, so a layout change cannot make these tests
         * agree with a stale assumption */
        ULONG hdr  = (ULONG)offsetof(TPDRV_CONFIG, Tokens);
        ULONG tcp0 = (ULONG)offsetof(TPDRV_CONFIG, UdpTokens);
        ULONG full = (ULONG)sizeof(TPDRV_CONFIG);
        CHECK(hdr == 16 && tcp0 == 144 && full == 272,
              "TPDRV_CONFIG layout moved (hdr=%lu udp@=%lu size=%lu) — the service mirror "
              "in src/wfp_ingress.rs pins the same numbers", hdr, tcp0, full);
        CHECK(TpdrvConfigBufferOk(full, 16, 16) == TRUE, "a complete request is accepted");
        CHECK(TpdrvConfigBufferOk(full, 0, 0) == TRUE, "counts of zero fit any full-size request");
        CHECK(TpdrvConfigBufferOk(tcp0, 0, 1) == FALSE,
              "claiming even ONE udp token without the udp array must be refused");
        CHECK(TpdrvConfigBufferOk(hdr, 0, 64) == FALSE,
              "THE BUG: 16-byte buffer + 64 udp tokens read past the buffer");
        CHECK(TpdrvConfigBufferOk(hdr + 2, 1, 0) == TRUE, "tcp token 1 fits right at the edge");
        CHECK(TpdrvConfigBufferOk(hdr, 1, 0) == FALSE, "and one byte short does not");
        CHECK(TpdrvConfigBufferOk(full, 65, 0) == FALSE, "an over-long tcp count is refused");
        CHECK(TpdrvConfigBufferOk(full, 0, 65) == FALSE, "an over-long udp count is refused");
        CHECK(TpdrvConfigBufferOk(0, 0, 0) == FALSE, "an empty buffer is refused");
    }

    /* ── UDP flow table: reserve / look up / release / exhaust ──────────────── */
    {
        UINT16 utoks[4] = {13000, 13001, 13002, 13003};
        UINT16 toks[3] = {12000, 12001, 12002};
        TP_FLOW_RECORD out;
        UINT16 got[TPDRV_MAX_TOKENS + 2];
        ULONG i, active;

        memset(&remote, 0, sizeof(remote));
        ((struct sockaddr_in*)&remote)->sin_family = AF_INET;
        ((struct sockaddr_in*)&remote)->sin_port = (unsigned short)htons(53);
        ((struct sockaddr_in*)&remote)->sin_addr.S_un.S_addr = htonl(0x08080808UL);
        memset(&local, 0, sizeof(local));
        ((struct sockaddr_in*)&local)->sin_family = AF_INET;
        ((struct sockaddr_in*)&local)->sin_port = (unsigned short)htons(40000);

        TpdrvApplyConfig(4321, 1, toks, 3, utoks, 4);

        CHECK(TpdrvUdpReserve(0xAA01, &remote, &local, 17, 555, &out) != 0, "first UDP flow gets a token");
        CHECK(out.magic == TP_FLOW_RECORD_MAGIC && out.proto == 17, "reserved record is well-formed");
        CHECK(TpdrvUdpLookup(out.tokenPort, &out) == TRUE, "the staged flow is findable by token");
        {
            UINT16 tok = out.tokenPort;
            CHECK(TpdrvUdpLookup(9999, &out) == FALSE, "an unknown token is not answered with a guess");
            CHECK(TpdrvUdpReleaseByFlow(tok) == tok, "release returns the token it freed");
            CHECK(TpdrvUdpLookup(tok, &out) == FALSE, "a released flow is gone (no stale destination)");
            CHECK(TpdrvUdpReleaseByFlow(tok) == 0, "double release is harmless");
        }

        /* the pool is finite; after that a new flow must be REFUSED, not queued */
        active = 0;
        for (i = 0; i < TPDRV_MAX_TOKENS + 1; i++)
        {
            got[i] = TpdrvUdpReserve(0xBB00 + i, &remote, &local, 17, 556, &out);
            if (got[i] != 0)
            {
                active++;
            }
        }
        /*
         * Capacity is the number of DISTINCT token ports, not the number of table
         * slots: the service resolves a redirected datagram's destination by token, and
         * a connected UDP socket only takes replies from the port it was sent to. Two
         * flows on one port is not sharing, it is dropping one of them — so the driver
         * must refuse before double-booking. (This replaced an earlier expectation of
         * TPDRV_MAX_TOKENS, which was the bug.)
         */
        CHECK(active == 4, "capacity is the distinct UDP token count (saw %u)", active);
        CHECK(got[4] == 0, "a fully booked port pool returns no token");
        CHECK(TpdrvUdpActiveFlows() == 4, "active count matches what was handed out");
        {
            ULONG a, b;
            int dup = 0;
            for (a = 0; a < active; a++)
                for (b = a + 1; b < active; b++)
                    if (got[a] == got[b]) dup = 1;
            CHECK(!dup, "no token port is ever handed to two live flows");
        }
        {
            UINT16 freed = got[3];
            CHECK(TpdrvUdpReleaseByFlow(freed) == freed, "free one slot");
            {
                UINT16 again = TpdrvUdpReserve(0xCC01, &remote, &local, 17, 557, &out);
                CHECK(again == freed, "the freed port is handed out again, in its place (%u)", (unsigned)again);
            }
        }
    }

    if (failures == 0)
    {
        printf("OK: driver encoders match the Rust spec byte for byte (%d checks)\n", checks);
        return 0;
    }
    printf("%d FAILURES\n", failures);
    return 1;
}
