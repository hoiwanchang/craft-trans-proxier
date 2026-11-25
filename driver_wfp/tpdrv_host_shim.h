/*
 * tpdrv_host_shim.h — lets tpdrv_wfp.c's DECISION code be compiled and RUN on a normal
 * machine, with the Fwps* DDIs replaced by recorded fakes (see test_classify.c).
 *
 * Why this exists: `driver_wfp/record.c` was already host-tested (byte encodings), and
 * `trans_proxier::wfp_callout_plan` is the Rust spec for the classify decision — but
 * nothing had ever executed the C that will run inside the kernel. Claiming "the C
 * mirrors the Rust spec" without running the C is exactly the self-consistent-oracle
 * mistake this directory has already been caught making once.
 *
 * Scope, and it matters: only the classify path is compiled here. The control device,
 * DriverEntry and unload are wrapped out of tpdrv_wfp.c under this macro — faking the I/O
 * manager would only ever agree with itself. What IS exercised is where a mistake costs a
 * network: rights handling, the anti-loop branches, the transport gate, token-pool
 * selection, the sockaddr rewrite, and the record handed to WFP.
 *
 * The struct layouts match, and are cross-checked by, layout_probe.c against the real
 * fwpsk.h / fwptypes.h.
 */
#ifndef _TPDRV_HOST_SHIM_H_
#define _TPDRV_HOST_SHIM_H_

#include <winsock2.h>
#include <ws2def.h>
#include <ws2ipdef.h>
#include <windows.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>

/*
 * Types the driver uses that the Windows headers already provide — NTSTATUS, ULONG,
 * HANDLE, PVOID, SIZE_T, GUID, BOOLEAN, TRUE/FALSE, FIELD_OFFSET, STATUS_SUCCESS — come
 * from them rather than being re-declared here, because a second, slightly different
 * declaration is exactly how a host check drifts away from the kernel.
 * Only the kernel-object pointers that the excluded device code mentions get a stand-in:
 */
typedef void* PDEVICE_OBJECT;
typedef void* PDRIVER_OBJECT;
typedef void* PIRP;
typedef unsigned long long UINT64;
typedef unsigned short UINT16;
typedef unsigned char UINT8;

#ifndef NTAPI
#define NTAPI
#endif
#ifndef UNREFERENCED_PARAMETER
#define UNREFERENCED_PARAMETER(x) (void)(x)
#endif
#ifndef C_ASSERT
#define C_ASSERT(e) typedef char __c_assert_[(e) ? 1 : -1]
#endif
#ifndef NT_SUCCESS
#define NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)
#endif
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

/* ntstatus.h in a real build; declared here so the fallback path still compiles. */
#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#endif
#ifndef KdPrint
#define KdPrint(x) do { } while (0)
#endif

/*
 * TPDRV_ALLOC: with POOL_FLAG_NON_PAGED left undefined, tpdrv_wfp.c selects its
 * ExAllocatePoolWithTag spelling — which is also the pre-2004-WDK branch, so that path
 * gets executed on every run of this test instead of never being read by a compiler.
 */
#ifndef NonPagedPoolNx
#define NonPagedPoolNx 0
#endif
static inline void*
ExAllocatePoolWithTag(unsigned pool, size_t bytes, unsigned tag)
{
    (void)pool; (void)tag;
    return calloc(1, bytes);   /* zeroed: the driver must not rely on uninitialised pool */
}

static inline void
ExFreePoolWithTag(void* p, unsigned tag)
{
    (void)tag;
    free(p);
}

/* ── FWP / FWPS declarations, transcribed from fwptypes.h + fwpsk.h ───────── */
typedef unsigned int FWP_ACTION_TYPE;
typedef unsigned char FWP_DATA_TYPE;
#ifndef FWP_EMPTY
#define FWP_EMPTY   0
#define FWP_UINT8   1
#define FWP_UINT16  2
#define FWP_UINT32  3
#define FWP_UINT64  4
#endif
#ifndef FWP_ACTION_BLOCK
#define FWP_ACTION_BLOCK                0x00001001U
#define FWP_ACTION_PERMIT               0x00001002U
#define FWP_ACTION_CALLOUT_TERMINATING  0x00005003U
#endif
#ifndef FWPS_RIGHT_ACTION_WRITE
#define FWPS_RIGHT_ACTION_WRITE         0x00000001U
#endif
/* fwptypes.h spells the "keep going" action as a flag combination; the test uses it as
 * the value the callback MUST overwrite, so a callback that returns without touching
 * actionType is caught rather than passed. */
#ifndef FWP_ACTION_FLAG_NON_TERMINATING
#define FWP_ACTION_FLAG_NON_TERMINATING (0x00001000UL)
#define FWP_ACTION_CONTINUE             (0x00000006UL | FWP_ACTION_FLAG_NON_TERMINATING)
#endif
#ifndef FWPS_CLASSIFY_FLAG_REAUTHORIZE_IF_MODIFIED_BY_OTHERS
#define FWPS_CLASSIFY_FLAG_REAUTHORIZE_IF_MODIFIED_BY_OTHERS 0x00000001U
#endif

typedef struct FWP_VALUE0_ {
    FWP_DATA_TYPE type;
    union {
        UINT8   uint8;
        UINT16  uint16;
        UINT32  uint32;
        UINT64* uint64;     /* a POINTER, exactly as the real union declares it */
    };
} FWP_VALUE0;

typedef struct FWPS_INCOMING_VALUE0_ { FWP_VALUE0 value; } FWPS_INCOMING_VALUE0;

typedef struct FWPS_INCOMING_VALUES0_ {
    UINT16                layerId;
    UINT32                valueLayerDataIndex;
    FWPS_INCOMING_VALUE0  incomingValue[32];
} FWPS_INCOMING_VALUES0;

typedef struct FWPS_INCOMING_METADATA_VALUES0_ {
    UINT64  currentMetadataValues;   /* the header's own member name */
    UINT64  reserved0;
    UINT64  reserved1;
    UINT64  flowHandle;
    UINT16  ipHeaderSize;
    UINT16  transportHeaderSize;
    UINT64  processPath;
    UINT32  processId;
    UINT64  token;
    UINT32  packageSidLength;
    PVOID   packageSid;
    UINT64  compartmentId;
    UINT32  flags;
    HANDLE  redirectRecords;
} FWPS_INCOMING_METADATA_VALUES0;

#ifndef FWPS_METADATA_FIELD_FLOW_HANDLE
#define FWPS_METADATA_FIELD_FLOW_HANDLE            0x00000002ULL
#define FWPS_METADATA_FIELD_PROCESS_ID             0x00000020ULL
#define FWPS_METADATA_FIELD_REDIRECT_RECORD_HANDLE 0x40000000ULL
#endif

#ifndef FWPS_IS_METADATA_FIELD_PRESENT
#define FWPS_IS_METADATA_FIELD_PRESENT(m, f) \
    ((((FWPS_INCOMING_METADATA_VALUES0*)(m))->currentMetadataValues & (UINT64)(f)) == (UINT64)(f))
#endif

typedef struct FWPS_FILTER1_ {
    FWP_ACTION_TYPE actionType;
    UINT64          filterId;
    UINT64          weight;
    UINT64          effectiveWeight;
    UINT32          flags;
    UINT64          context;
} FWPS_FILTER1;

typedef struct FWPS_CLASSIFY_OUT0_ {
    FWP_ACTION_TYPE actionType;
    UINT64          outContext;
    UINT64          filterId;
    UINT64          rights;
    UINT32          flags;
    UINT32          reserved;
} FWPS_CLASSIFY_OUT0;

typedef struct _FWPS_CONNECT_REQUEST0 {
    SOCKADDR_STORAGE localAddressAndPort;
    SOCKADDR_STORAGE remoteAddressAndPort;
    UINT64           portReservationToken;
    DWORD            localRedirectTargetPID;
    struct _FWPS_CONNECT_REQUEST0* previousVersion;
    UINT64           modifierFilterId;
    HANDLE           localRedirectHandle;
    void*            localRedirectContext;
    SIZE_T           localRedirectContextSize;
} FWPS_CONNECT_REQUEST0;

typedef enum FWPS_CALLOUT_NOTIFY_TYPE_ {
    FWPS_CALLOUT_NOTIFY_ADD_FILTER = 0,
    FWPS_CALLOUT_NOTIFY_DELETE_FILTER = 1
} FWPS_CALLOUT_NOTIFY_TYPE;

/* The shape of the callback under test, so the test calls it the way the engine would. */
typedef void (*TpdrvClassifyFn)(const FWPS_INCOMING_VALUES0*,
                                const FWPS_INCOMING_METADATA_VALUES0*,
                                void*, const void*, const FWPS_FILTER1*,
                                UINT64, FWPS_CLASSIFY_OUT0*);

/* ── the DDIs, implemented by test_classify.c ────────────────────────────── */
typedef enum FWPS_CONNECTION_REDIRECT_STATE_ {
    FWPS_CONNECTION_NOT_REDIRECTED = 0,
    FWPS_CONNECTION_REDIRECTED_BY_SELF = 1,
    FWPS_CONNECTION_PREVIOUSLY_REDIRECTED_BY_SELF = 2,
    FWPS_CONNECTION_REDIRECTED_BY_OTHER = 3
} FWPS_CONNECTION_REDIRECT_STATE;

extern FWPS_CONNECTION_REDIRECT_STATE g_fake_redirect_state;
extern int g_fake_acquire_fails;
extern int g_calls_acquire, g_calls_release, g_calls_apply, g_calls_associate;
extern UINT64 g_last_apply_flags;
extern void* g_last_associated_ctx;

NTSTATUS FwpsAcquireClassifyHandle0(void* ctx, UINT32 flags, UINT64* handle);
void     FwpsReleaseClassifyHandle0(UINT64 handle);
NTSTATUS FwpsAcquireWritableLayerDataPointer0(UINT64 handle, UINT64 filterId, UINT32 flags,
                                              void** out, FWPS_CLASSIFY_OUT0* classifyOut);
void     FwpsApplyModifiedLayerData0(UINT64 handle, void* data, UINT32 flags);
NTSTATUS FwpsFlowAssociateContext0(UINT64 flowId, UINT16 layerId, UINT32 calloutId, UINT64 ctx);
FWPS_CONNECTION_REDIRECT_STATE FwpsQueryConnectionRedirectState0(HANDLE recs, HANDLE h, void** ctx);

#endif /* _TPDRV_HOST_SHIM_H_ */
