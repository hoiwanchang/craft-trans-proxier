/*
 * wdk_shim.h — lets an ordinary C compiler check tpdrv_wfp.c on a machine without
 * the WDK. Enabled only by -DTPDRV_SYNTAX_CHECK; the real build includes <fwpsk.h>.
 *
 * WHAT THIS CHECKS (and what it caught, see driver_wfp/README.md):
 *   every identifier exists; every Fwps / Io / Ex call has the documented number and
 *   kind of arguments; no variable is read before it is written; every path returns
 *   what its type says; the callout struct is filled with functions whose signatures
 *   match the typedefs. Those are the failure modes that a "never compiled" file is
 *   most likely to hide, and they are all cheap to fix before a VM build.
 *
 * AS OF 2026-11-25 THE REAL HEADERS ARE ON THIS MACHINE (Microsoft.Windows.WDK.x64 is
 * distributable as a zip): build_cl.ps1 compiles AND links tpdrv_wfp.sys with MSVC, and
 * that build corrected four things this transcription had wrong — FWP_VALUE0 has no
 * uint64Data (its 64-bit case is `UINT64 *uint64`, and IP_PROTOCOL is FWP_UINT8),
 * AcquireWritableLayerDataPointer0's filterId is UINT64, ApplyModifiedLayerData0 returns
 * VOID, and FWPS_CLASSIFY_HANDLE is a name this file invents for what fwpsk.h calls a
 * plain UINT64. The shim carries those corrections so both checks agree; the MSVC build
 * is the authority.
 *
 * WHAT IT DOES NOT CHECK:
 *   the LAYOUT of the structures marked [indicative] below. Only the members this
 *   driver touches by name are declared, and members we never read are omitted, so
 *   offsets here are NOT the WDK's. That is deliberate: a wrong member name cannot
 *   compile on either side, which is the property worth keeping, while a hand-copied
 *   full layout would only pretend to be authoritative. The WDK build remains the
 *   authority for layout, exactly as README.md says.
 *
 * The declarations marked [DDI] were transcribed from the Microsoft DDI page named
 * in the comment above each one, read 2026-11-25.
 */
#ifndef _TPDRV_WDK_SHIM_H_
#define _TPDRV_WDK_SHIM_H_

/* MinGW-w64 ships Microsoft's own ddk/ntddk.h, which gives us the real
 * DRIVER_OBJECT / DEVICE_OBJECT / IRP / UNICODE_STRING / NTSTATUS declarations.
 * Using them instead of hand-written copies keeps the whole IOCTL and entry/exit
 * half of this driver checked against the genuine article. */
#include <ntddk.h>
#include <string.h>
#include <stdlib.h>

/* ---- ExAllocatePool2: newer than the pool API this header copy knows ---- */
#ifndef POOL_FLAG_NON_PAGED
typedef UINT64 POOL_FLAGS;
#define POOL_FLAG_NON_PAGED            0x0000000000000040ULL
#define POOL_FLAG_NON_PAGED_EXECUTE    0x0000000000000080ULL
PVOID ExAllocatePool2(POOL_FLAGS Flags, SIZE_T NumberOfBytes, ULONG Tag);
#endif

#ifndef C_ASSERT
#define C_ASSERT(e) typedef char __C_ASSERT__[(e) ? 1 : -1]
#endif

/* The kernel headers do not carry DWORD, and the real driver TU gets it from the WDK's
 * windef via fwpsk.h; fwpsk.h spells localRedirectTargetPID as a DWORD, so it goes here. */
typedef unsigned long DWORD;

/* UFIELD_OFFSET comes from ntdef.h in the WDK; this header copy predates it. */
#ifndef UFIELD_OFFSET
#define UFIELD_OFFSET(type, field) ((UINT32)FIELD_OFFSET(type, field))
#endif

/* ---- internet addresses ---------------------------------------------------
 *
 * fwpsk.h declares FWPS_CONNECT_REQUEST0's endpoints as SOCKADDR_STORAGE, and the WDK
 * gets those types from its own copies of ws2def.h/ws2ipdef.h. They cannot be included
 * here: a user-mode include cannot follow ntddk.h in one translation unit (MinGW
 * proves it by failing in minwinbase.h). So the five structs are transcribed from
 * ws2def.h/ws2ipdef.h, which is the same text the WDK ships.
 *
 * This is NOT where the byte-level spellings are proved. record.c compiles and RUNS
 * against the real MinGW winsock2.h in test_record.c, and that is what shows
 * sin_addr.S_un.S_addr and sin6_addr.u.Byte are the members the code means. Here they
 * only need to exist so the kernel TU can be type-checked at all.
 */
typedef unsigned short ADDRESS_FAMILY, *PADDRESS_FAMILY;

#ifndef AF_INET
#define AF_INET   2
#endif
#ifndef AF_INET6
#define AF_INET6 23
#endif
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

typedef struct in_addr {
    union {
        struct { unsigned char s_b1, s_b2, s_b3, s_b4; } S_un_b;
        struct { unsigned short s_w1, s_w2; } S_un_w;
        unsigned long S_addr;
    } S_un;
} IN_ADDR, *PIN_ADDR;

typedef struct sockaddr {
    ADDRESS_FAMILY sa_family;
    char sa_data[14];
} SOCKADDR, *PSOCKADDR;

typedef struct sockaddr_in {
    short sin_family;
    unsigned short sin_port;
    IN_ADDR sin_addr;
    char sin_zero[8];
} SOCKADDR_IN, *PSOCKADDR_IN;

typedef struct in6_addr {
    union {
        unsigned char Byte[16];
        unsigned short Word[8];
    } u;
} IN6_ADDR, *PIN6_ADDR;

typedef struct sockaddr_in6 {
    unsigned short sin6_family;
    unsigned short sin6_port;
    unsigned long sin6_flowinfo;
    IN6_ADDR sin6_addr;
    unsigned long sin6_scope_id;
} SOCKADDR_IN6, *PSOCKADDR_IN6;

/* ws2def.h: 126 bytes of padding after the family, so the whole thing is 128 and
 * aligns to the strictest socket address. */
typedef struct sockaddr_storage {
    ADDRESS_FAMILY ss_family;
    char __ss_padding[126 - sizeof(short)];
} SOCKADDR_STORAGE, *PSOCKADDR_STORAGE;

/*
 * -DTPDRV_TEST_LEGACY_POOL hides the 2004-era pool API so the OLDER spelling in
 * tpdrv_wfp.c (TPDRV_ALLOC → ExAllocatePoolWithTag) is the one that gets compiled.
 * Without this, the compatibility branch is code nobody has ever asked a compiler to
 * read, which is exactly the situation that produced the six defects above.
 */
#ifdef TPDRV_TEST_LEGACY_POOL
#undef POOL_FLAG_NON_PAGED
PVOID ExAllocatePoolWithTag(UINT32 PoolType, SIZE_T NumberOfBytes, ULONG Tag);
#ifndef NonPagedPoolNx
#define NonPagedPoolNx 0
#endif
#endif

/* ---- FWP value / action ---- */

/* ntstatus.h in a real build; declared here so the fallback path still compiles. */
#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#endif
typedef UINT32 FWP_ACTION_TYPE;
typedef UINT8  FWP_DATA_TYPE;

/* [DDI] fwpstypes.h / fwptypes.h — union trimmed to the members we read. */
typedef struct FWP_VALUE0_ {
    FWP_DATA_TYPE type;
    union {
        UINT8  uint8;
        UINT16 uint16;
        UINT32 uint32;
        UINT64* uint64; /* fwpstypes: a POINTER, not a value */
    };
} FWP_VALUE0;

/* fwptypes.h data-type tags (values pinned by driver_wfp/abi_check.c). */
#define FWP_EMPTY   0
#define FWP_UINT8   1
#define FWP_UINT16  2
#define FWP_UINT32  3
#define FWP_UINT64  4

#define FWP_ACTION_PERMIT              0x00001002U
#define FWP_ACTION_BLOCK               0x00001001U
#define FWP_ACTION_CALLOUT_TERMINATING 0x00005003U

/* fwpsk.h 10.0.26100, read from the WDK package header on 2026-11-25 — tpdrv_wfp.c
 * applies it on the 'another callout already redirected this flow' path. */
#ifndef FWPS_CLASSIFY_FLAG_REAUTHORIZE_IF_MODIFIED_BY_OTHERS
#define FWPS_CLASSIFY_FLAG_REAUTHORIZE_IF_MODIFIED_BY_OTHERS 0x00000001U
#endif

/* [DDI] fwpstypes.h: FWPS_RIGHT_ACTION_WRITE */
#define FWPS_RIGHT_ACTION_WRITE        0x00000001U

/* ---- classify inputs ---- */
typedef struct FWPS_INCOMING_VALUE0_ {
    FWP_VALUE0 value;
} FWPS_INCOMING_VALUE0;

/* [indicative] FWPS_INCOMING_VALUES0 — layerId and incomingValue are the two members
 * this driver reads; the members between them are omitted, so do not trust offsets. */
typedef struct FWPS_INCOMING_VALUES0_ {
    UINT16                layerId;
    UINT32                valueLayerDataIndex;
    FWPS_INCOMING_VALUE0  incomingValue[1];
} FWPS_INCOMING_VALUES0;

/* [indicative] FWPS_INCOMING_METADATA_VALUES0 — same rule: the four members named
 * here are the only ones this driver reads. */
typedef struct FWPS_INCOMING_METADATA_VALUES0_ {
    UINT16  layerId;
    UINT64  flowHandle;
    UINT32  processId;
    HANDLE  redirectRecords;
    UINT64  currentMetadataValues;   /* fwpsk.h name; NOT ...FieldFlags */
} FWPS_INCOMING_METADATA_VALUES0;

/* [DDI] fwpsk.h, "Metadata Fields" doc page. The NUMBERS here are indicative only —
 * fwpsk.h supplies the real ones, and nothing outside this shim depends on them. */
#define FWPS_METADATA_FIELD_FLOW_HANDLE            0x0000000000000002ULL
#define FWPS_METADATA_FIELD_PROCESS_ID             0x0000000000000020ULL
#define FWPS_METADATA_FIELD_REDIRECT_RECORD_HANDLE 0x0000000040000000ULL

/* [DDI] fwpsk.h: the documented expansion tests the flag bits in
 * currentMetadataValues — the member name below is the header's, and the bit values are
 * the header's (PROCESS_ID is 0x20, not the 0x40 an earlier draft guessed: the
 * metadata-presence gates are the driver's only defence against reading a pid that was
 * never indicated, so a fiction here would have made the type-check vacuous). */
#ifndef FWPS_IS_METADATA_FIELD_PRESENT
#define FWPS_IS_METADATA_FIELD_PRESENT(metadataValues, fieldIdentifier)              \
    ((((FWPS_INCOMING_METADATA_VALUES0*)(metadataValues))                             \
          ->currentMetadataValues & (UINT64)(fieldIdentifier)) ==                      \
     (UINT64)(fieldIdentifier))
#endif

/* [DDI+SDK] fwpstypes.h: FWPS_FILTER1.filterId is UINT64, and the real
 * FwpsAcquireWritableLayerDataPointer0 takes that same UINT64 — there is no narrowing to
 * a UINT16, which an earlier version of this file (and the driver) wrongly assumed. */
typedef struct FWPS_FILTER1_ {
    FWP_ACTION_TYPE actionType;
    UINT64          filterId;
    UINT64          weight;
    UINT64          effectiveWeight;
    UINT32          flags;
    UINT64          context;
} FWPS_FILTER1;

/* [DDI] fwpstypes.h: FWPS_CLASSIFY_OUT0 */
typedef struct FWPS_CLASSIFY_OUT0_ {
    FWP_ACTION_TYPE actionType;
    UINT64          outContext;
    UINT64          filterId;
    UINT64          rights;
    UINT32          flags;
    UINT32          reserved;
} FWPS_CLASSIFY_OUT0;

typedef UINT64 FWPS_CLASSIFY_HANDLE;

/* [DDI] fwpsk.h: FWPS_CONNECT_REQUEST0 — copied verbatim from the DDI syntax block:
 *   SOCKADDR_STORAGE localAddressAndPort;
 *   SOCKADDR_STORAGE remoteAddressAndPort;
 *   UINT64           portReservationToken;
 *   DWORD            localRedirectTargetPID;
 *   struct _FWPS_CONNECT_REQUEST0 *previousVersion;
 *   UINT64           modifierFilterId;
 *   HANDLE           localRedirectHandle;
 *   void            *localRedirectContext;
 *   SIZE_T           localRedirectContextSize;
 * The page also states the rule this driver relies on: from Windows 8 on, the memory
 * handed to localRedirectContext is owned by WFP and freed when the proxied flow is
 * deleted — so flowDeleteFn must NOT free it. */
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
} FWPS_CONNECT_REQUEST0, *PFWPS_CONNECT_REQUEST0;

/* ---- the callout ---- */

/* [DDI] nc-fwpsk-fwps_callout_classify_fn1 */
typedef void(NTAPI* FWPS_CALLOUT_CLASSIFY_FN1)(
    const FWPS_INCOMING_VALUES0* InFixedValues,
    const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
    void* LayerData,
    const void* ClassifyContext,
    const FWPS_FILTER1* Filter,
    UINT64 FlowContext,
    FWPS_CLASSIFY_OUT0* ClassifyOut);

/* [DDI] nc-fwpsk-fwps_callout_notify_fn1 — THREE parameters and an NTSTATUS:
 *   NTSTATUS f(FWPS_CALLOUT_NOTIFY_TYPE notifyType, const GUID *filterKey,
 *              FWPS_FILTER1 *filter)
 * Returning anything but STATUS_SUCCESS for ADD_FILTER stops the filter being added,
 * so the signature matters as much as the body. */
typedef enum FWPS_CALLOUT_NOTIFY_TYPE_ {
    FWPS_CALLOUT_NOTIFY_ADD_FILTER    = 0,
    FWPS_CALLOUT_NOTIFY_DELETE_FILTER = 1,
    FWPS_CALLOUT_NOTIFY_TYPE_MAX      = 2
} FWPS_CALLOUT_NOTIFY_TYPE;

typedef NTSTATUS(NTAPI* FWPS_CALLOUT_NOTIFY_FN1)(
    FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    const GUID* filterKey,
    FWPS_FILTER1* filter);

/* [DDI] nc-fwpsk-fwps_callout_flow_delete_notify_fn0 — three scalars, no argument
 * struct, and the flowContext is what FwpsFlowAssociateContext0 stored. */
typedef void(NTAPI* FWPS_CALLOUT_FLOW_DELETE_NOTIFY_FN0)(
    UINT16 layerId,
    UINT32 calloutId,
    UINT64 flowContext);

/* [DDI] ns-fwpsk-fwps_callout1_ — verbatim member list. */
typedef struct FWPS_CALLOUT1_ {
    GUID calloutKey;
    UINT32 flags;
    FWPS_CALLOUT_CLASSIFY_FN1 classifyFn;
    FWPS_CALLOUT_NOTIFY_FN1 notifyFn;
    FWPS_CALLOUT_FLOW_DELETE_NOTIFY_FN0 flowDeleteFn;
} FWPS_CALLOUT1;

/* [DDI] nf-fwpsk-fwpsqueryconnectionredirectstate0 */
typedef enum FWPS_CONNECTION_REDIRECT_STATE_ {
    FWPS_CONNECTION_NOT_REDIRECTED = 0,
    FWPS_CONNECTION_REDIRECTED_BY_SELF = 1,
    FWPS_CONNECTION_PREVIOUSLY_REDIRECTED_BY_SELF = 2,
    FWPS_CONNECTION_REDIRECTED_BY_OTHER = 3,
    FWPS_CONNECTION_PREVIOUSLY_REDIRECTED_BY_OTHER = 4,
    FWPS_CONNECTION_REDIRECT_STATE_MAX = 5
} FWPS_CONNECTION_REDIRECT_STATE;

/* ---- the DDIs this driver calls ---- */

NTSTATUS FwpsCalloutRegister1(void* deviceObject, const FWPS_CALLOUT1* callout, UINT32* calloutId);
void     FwpsCalloutUnregisterById0(const UINT32 calloutId);

NTSTATUS FwpsRedirectHandleCreate0(const GUID* providerKey, UINT32 flags, HANDLE* redirectHandle);
void     FwpsRedirectHandleDestroy0(HANDLE redirectHandle);

FWPS_CONNECTION_REDIRECT_STATE FwpsQueryConnectionRedirectState0(
    HANDLE redirectRecords, HANDLE redirectHandle, void** redirectContext);

NTSTATUS FwpsAcquireClassifyHandle0(void* classifyContext, UINT32 flags,
                                    FWPS_CLASSIFY_HANDLE* classifyHandle);
void     FwpsReleaseClassifyHandle0(FWPS_CLASSIFY_HANDLE classifyHandle);

NTSTATUS FwpsAcquireWritableLayerDataPointer0(FWPS_CLASSIFY_HANDLE classifyHandle,
                                              UINT64 filterId,
                                              UINT32 flags,
                                              void** writableLayerData,
                                              _Inout_opt_ FWPS_CLASSIFY_OUT0* classifyOut);
/* fwpsk.h: VOID, not NTSTATUS — the engine cannot refuse an apply, which is why every
 * path out of a successful acquire must restore actionType by hand. */
void FwpsApplyModifiedLayerData0(FWPS_CLASSIFY_HANDLE classifyHandle,
                                 void* modifiedLayerData,
                                 UINT32 flags);

NTSTATUS FwpsFlowAssociateContext0(UINT64 flowHandle, UINT16 layerId, UINT32 calloutId,
                                   UINT64 flowContext);

/* KdPrint is a debug-only macro in the WDK; a no-op here keeps the format strings
 * visible in the source without needing the DBG machinery. */
#ifndef KdPrint
#define KdPrint(x) do { } while (0)
#endif

#endif /* _TPDRV_WDK_SHIM_H_ */
