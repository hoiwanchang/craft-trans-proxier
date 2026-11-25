/*
 * tpdrv_wfp.h — shared contract between the callout driver and the service.
 *
 * TP_FLOW_RECORD MUST match trans_proxier::wfp_classify::FlowRecord byte for byte
 * (72 bytes; offsets asserted with C_ASSERT in tpdrv_wfp.c and by Rust tests).
 */
#ifndef _TPDRV_WFP_H_
#define _TPDRV_WFP_H_

/* the kernel TU gets these from the driver sources; the host TU (test_record.c)
 * needs winsock2 BEFORE windows.h or the legacy winsock.h sneaks in */
#ifdef _NTDDK_
#include <ntddk.h>
#else
#include <winsock2.h>
#include <windows.h>
#include <stddef.h>
#endif

#define NT_DEVICE_NAME     L"\\Device\\TpDrvWfp"
#define NTDOS_DEVICE_NAME  L"\\DosDevices\\TpDrvWfp"

#ifndef IOCTL_TPDRV_SET_CONFIG
#define FILE_DEVICE_TPDRV 0x8000
#define IOCTL_TPDRV_SET_CONFIG  CTL_CODE(FILE_DEVICE_TPDRV, 0x800, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_TPDRV_GET_STATUS  CTL_CODE(FILE_DEVICE_TPDRV, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
/*
 * A redirected DATAGRAM has no accepted socket to ask for its redirect context, so the
 * service queries the driver's flow table instead: input UINT16 token port, output
 * TP_FLOW_RECORD. (TCP does not need this — its accepted socket carries the context.)
 */
#define IOCTL_TPDRV_QUERY_FLOW  CTL_CODE(FILE_DEVICE_TPDRV, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif

/* keep in sync with wfp_ingress::TOKEN_POOL */
#define TPDRV_MAX_TOKENS 64

#define TP_FLOW_RECORD_MAGIC 0x50525846u   /* "PRXF" */
#define TP_VERDICT_PERMIT    0
#define TP_VERDICT_REDIRECT  1
#define TP_VERDICT_BLOCK     2

#pragma pack(push, 1)
typedef struct _TP_FLOW_RECORD {
    UINT32 magic;            /* 0  */
    UINT16 family;           /* 4  AF_INET / AF_INET6 */
    UINT16 portBe;           /* 6  original remote port, network order */
    UINT8  addr[16];         /* 8  original remote address */
    UINT32 pid;              /* 24 connecting process */
    UINT32 chain;            /* 28 0: the service picks the chain from the profile */
    UINT8  verdict;          /* 32 */
    UINT8  proto;            /* 33 IPPROTO_TCP / IPPROTO_UDP */
    UINT16 tokenPort;        /* 34 engine listener this flow was sent to */
    UINT8  pad0[4];          /* 36 */
    UINT64 flowId;           /* 40 0: filled in only where available */
    UINT8  localAddr[16];    /* 48 the app's own endpoint at classify time */
    UINT16 localPortBe;      /* 64 */
    UINT8  pad1[6];          /* 66 */
} TP_FLOW_RECORD, *PTP_FLOW_RECORD;
#pragma pack(pop)

typedef struct _TPDRV_CONFIG {
    ULONG  ProxyPid;                              /* owner of the token listeners */
    ULONG  Enabled;                               /* master switch for the redirect */
    ULONG  TokenCount;                            /* entries in Tokens (TCP) */
    ULONG  UdpTokenCount;                         /* entries in UdpTokens */
    UINT16 Tokens[TPDRV_MAX_TOKENS];              /* loopback TCP ports, listening */
    UINT16 UdpTokens[TPDRV_MAX_TOKENS];           /* loopback UDP ports, one per flow */
} TPDRV_CONFIG, *PTPDRV_CONFIG;

/* one live UDP redirect: token ↔ flow, so flowDelete can hand the token back */
typedef struct _TP_FLOW_ENTRY {
    UINT16        inUse;
    UINT16        tokenPort;
    UINT64        flowHandle;
    TP_FLOW_RECORD record;
} TP_FLOW_ENTRY, *PTP_FLOW_ENTRY;

typedef struct _TPDRV_STATUS {
    ULONG Enabled;
    ULONG ProxyPid;
    ULONG TokenCount;
    ULONG UdpTokenCount;
    ULONG UdpActiveFlows;
    ULONG CalloutsRegistered;
    ULONG RedirectHandleValid;
    /*
     * Datagrams the callout could NOT track, so far. A UDP flow is only redirectable
     * while the engine indicates a flow handle — that handle is what carries the token
     * back to flowDeleteFn — and without it the choice is between leaking the app's real
     * address (send it to a token nobody will ever free) and leaving the flow direct.
     * This driver chooses direct, which is the safe side of the trade but SILENT, so it
     * counts them instead: `trans-proxier wfp --verify` prints this number, and a non-zero
     * value means "some of your UDP is not being proxied, and here is why".
     */
    ULONG UdpUntrackable;
} TPDRV_STATUS, *PTPDRV_STATUS;

/* the service mirrors this layout in trans_proxier::wfp_ingress::DriverStatus */
#ifndef TPDRV_HOST_TEST
C_ASSERT(sizeof(TPDRV_STATUS) == 32);
#endif

#endif /* _TPDRV_WFP_H_ */
