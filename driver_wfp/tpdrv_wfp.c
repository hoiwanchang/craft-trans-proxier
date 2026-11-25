/*
 * tpdrv_wfp.c — WFP connect-redirect callout for trans-proxier.
 *
 * Read driver_wfp/README.md first. In short: this file is C because the structs it
 * touches live in the WDK's fwpsk.h, which is absent from the machine this project
 * was developed on; C lets the WDK compiler validate every member name and type,
 * where a hand-copied Rust layout would fail silently and corrupt memory at IRQL.
 *
 * The decision logic and the byte layouts it produces are specified and tested in
 * Rust (trans_proxier::wfp_callout_plan, trans_proxier::wfp_classify::FlowRecord);
 * this file mirrors them. If the two disagree, the Rust tests are the reference.
 *
 * Design notes that are easy to get wrong:
 *   - No per-flow policy here. The service installs one filter per whitelisted app
 *     (src/wfp.rs), so this callback only runs for traffic the user selected.
 *   - The ORIGINAL destination travels in localRedirectContext, which WFP owns and
 *     frees with the flow (Windows 8+). The proxy reads it back with
 *     SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT — already implemented and
 *     live-tested in src/wfp_ingress.rs.
 *   - FwpsQueryConnectionRedirectState0 runs before anything is modified. Skipping
 *     it redirects our own proxied egress forever.
 *   - Token ports are just a set of loopback listeners the service already owns.
 *     Because every accepted socket carries its own context, two flows may use the
 *     same token concurrently, so the pool needs no in-use bookkeeping (and the
 *     classify path takes no lock).
 *   - Classify runs at DISPATCH_LEVEL: no pipes, no user-mode calls, no pageable
 *     memory.
 *
 * STATUS: BUILT. driver_wfp/build_cl.ps1 compiles this file and record.c with MSVC
 * against the real fwpsk.h and links out\tpdrv_wfp.sys (x64, subsystem Native, ten
 * Fwps* imports resolving to fwpkclnt.sys). It has NOT been signed and NEVER been
 * loaded, so every claim below about run-time behaviour remains unverified.
 *
 * That first compile corrected four things the DDI-page transcription had wrong — read
 * the table in README.md ("Status, honestly") before touching any signature here:
 * FWP_VALUE0 has no uint64Data (its 64-bit case is `UINT64 *uint64`, and IP_PROTOCOL is
 * FWP_UINT8); there is no FWPS_CLASSIFY_HANDLE typedef (the handle is a plain UINT64);
 * FwpsAcquireWritableLayerDataPointer0 takes a UINT64 filterId, not a narrowed UINT16;
 * and FwpsApplyModifiedLayerData0 returns void, which is precisely why the action
 * restore has to be done by hand on every path out of a successful acquire.
 *
 * Before that, the only compiler ever to read this file was gcc: build.ps1 -Test
 * type-checks both kernel translation units against wdk_shim.h plus MinGW's copy of
 * Microsoft's own ddk/ntddk.h, and that check found five defects (see README.md).
 *
 * Every call signature used here was read off the Microsoft DDI page for that
 * function on 2026-11-25, because a wrong argument of the same size does not
 * reliably fail to compile. In particular:
 *   FwpsQueryConnectionRedirectState0(redirectRecords, redirectHandle,
 *       void** redirectContext) -> FWPS_CONNECTION_REDIRECT_STATE   [returns state]
 *   FwpsAcquireWritableLayerDataPointer0(classifyHandle, filterId, flags,
 *       writableLayerData, classifyOut)                              [2nd is filterId]
 *   FwpsApplyModifiedLayerData0(classifyHandle, modifiedLayerData, flags)
 *   FwpsAcquireClassifyHandle0(classifyContext, flags, &classifyHandle)
 *   FwpsRedirectHandleCreate0(providerGuid, flags, &handle)   Win8+, PASSIVE_LEVEL
 *   FwpsCalloutRegister1(deviceObject, &FWPS_CALLOUT1, &calloutId)
 * and that AcquireWritableLayerDataPointer0 sets classifyOut->actionType to
 * FWP_ACTION_BLOCK, so every path out of a successful acquire must restore PERMIT.
 *
 * Verified the same way on 2026-11-25 and reflected in the code above:
 *   FwpsFlowAssociateContext0(flowHandle, layerId, calloutId, flowContext)  [not
 *       classifyHandle first, and the context must be non-zero and requires a
 *       flowDeleteFn to be registered — which we do]
 *   flowDeleteFn(UINT16 layerId, UINT32 calloutId, UINT64 flowContext)      [three
 *       scalars; there is no FWPS_FLOW_DELETE_ARGUMENT parameter]
 *   metadata fields are only valid when flagged present, so processId, flowHandle and
 *       redirectRecords are each read behind FWPS_IS_METADATA_FIELD_PRESENT.
 *
 * Also verified, and it changes how the driver must be deployed: until a callout is
 * registered, the engine treats filters whose action is FWP_ACTION_CALLOUT_TERMINATING
 * as FWP_ACTION_BLOCK. That is why every filter the control plane installs carries
 * FWPM_FILTER_FLAG_PERMIT_IF_CALLOUT_UNREGISTERED (src/wfp.rs) — otherwise a service
 * that came up before the driver would cut the network out from under exactly the
 * programs the user whitelisted.
 *
 * On classifyOut->rights, following the WFP sampler instead of my first reading: the
 * redirect body only runs while FWPS_RIGHT_ACTION_WRITE is set; acquiring the writable
 * layer data CLEARS it; and every path that ends up changing nothing must give it back
 * so the rest of the filter stack can still act. A path that really did redirect
 * leaves it cleared — that is how a callout says "this one is mine".
 *
 * What still rests on fwpsk.h alone: the LAYOUT of the FWPS_* structures. The shim
 * declares only the members this file touches, in the order the DDI pages show them,
 * and omits the ones between, so offsets there are not the WDK's. That is why this
 * file accesses every kernel structure by name and never by offset — and why it never
 * reads FWPS_INCOMING_VALUES0's value-count member at all.
 */

#if defined(TPDRV_HOST_TEST)
/* Unit-testing the classify decision with recorded fakes for the Fwps* DDIs. The control
 * device and DriverEntry are compiled out below: faking them would prove nothing. */
#include "tpdrv_host_shim.h"
#elif defined(TPDRV_SYNTAX_CHECK)
/* No WDK on this machine: wdk_shim.h supplies the same declarations, transcribed from
 * the DDI pages, so `gcc -fsyntax-only` can check this file's internal consistency.
 * That file's header comment states what such a check can and cannot prove. */
#include "wdk_shim.h"
#else
#include <ndis.h>
#include <fwpsk.h>
#include <fwpmu.h>
#include <ntstrsafe.h>
#endif

#include "tpdrv_wfp.h"
#include "record.h"

/*
 * Field indices for FWPS_INCOMING_VALUES0.incomingValue[] at the connect-redirect
 * layers. Windows Kits/10/Include/10.0.26100.0/um/fwpsu.h numbers ALE_APP_ID=0,
 * ALE_USER_ID=1, IP_LOCAL_ADDRESS=2, IP_LOCAL_ADDRESS_TYPE=3, IP_LOCAL_PORT=4,
 * IP_PROTOCOL=5, IP_REMOTE_ADDRESS=6, IP_DESTINATION_ADDRESS_TYPE=7,
 * IP_REMOTE_PORT=8, FLAGS=9 — identically for the V4 and V6 enums, which is why one
 * constant serves both.
 */
#define TP_FIELD_IP_PROTOCOL 5

#define TPDRV_POOL_TAG 'pWrT'

/*
 * Toolchain compatibility, so that the FIRST build on the operator's WDK is not spent
 * discovering these. `ExAllocatePool2` + `POOL_FLAG_*` exist only from the 2004 WDK on;
 * `UFIELD_OFFSET` lives in ntdef.h but not in every header set. Both have an older,
 * equivalent spelling, so the choice is made at preprocessing time and the resulting
 * allocation is the same nonpaged, non-executable pool the redirect context requires
 * (WFP owns and frees that context, and it frees with the plain pool free — which is why
 * either allocator is correct here and only a mismatch would be fatal).
 */
#ifndef UFIELD_OFFSET
#define UFIELD_OFFSET(type, field) ((ULONG)FIELD_OFFSET(type, field))
#endif

#if defined(POOL_FLAG_NON_PAGED)
#define TPDRV_ALLOC(_bytes) ExAllocatePool2(POOL_FLAG_NON_PAGED, (_bytes), TPDRV_POOL_TAG)
#else
/* Older WDK: NonPagedPoolNx is itself the pool type that forbids executable pool. */
#if !defined(NonPagedPoolNx)
#define NonPagedPoolNx NonPagedPool
#endif
__declspec(deprecated("ExAllocatePool2 unavailable in this WDK")) static inline PVOID
TpdrvAllocPool2Compat(SIZE_T bytes)
{
    return ExAllocatePoolWithTag(NonPagedPoolNx, bytes, TPDRV_POOL_TAG);
}
#define TPDRV_ALLOC(_bytes) TpdrvAllocPool2Compat(_bytes)
#endif

/* MUST equal trans_proxier::wfp::REDIRECT_CALLOUT: d7a1f002-2222-4333-9999-999999999999 */
static const GUID g_CalloutKey =
    {0xd7a1f002, 0x2222, 0x4333, {9, 9, 9, 9, 9, 9, 9, 9}};

/* FwpsRedirectHandleCreate0 wants a PROVIDER guid; keep it separate from the
 * callout key so a future second callout in the same driver stays distinguishable. */
static const GUID g_ProviderKey =
    {0xd7a1f003, 0x3333, 0x4444, {10, 10, 10, 10, 10, 10, 10, 10}};

static PDEVICE_OBJECT g_DeviceObject = NULL;
static HANDLE g_RedirectHandle = NULL;
static UINT32 g_CalloutId = 0;
static volatile LONG g_CalloutRegistered = 0;

#ifdef TPDRV_HOST_TEST
/*
 * The host test cannot run DriverEntry (that needs the I/O manager), so these stand in for
 * what FwpsRedirectHandleCreate0 and FwpsCalloutRegister1 would have produced. Without
 * them the test could not distinguish "the driver stored the redirect handle" from "the
 * handle was never set in the first place" — and a loopback redirect without that handle
 * is exactly the case the engine silently refuses.
 */
HANDLE TpdrvTestSetRedirectHandle(HANDLE h)
{
    HANDLE old = g_RedirectHandle;
    g_RedirectHandle = h;
    return old;
}

UINT32 TpdrvTestSetCalloutId(UINT32 id)
{
    UINT32 old = g_CalloutId;
    g_CalloutId = id;
    return old;
}
#endif


/* --- the callout ----------------------------------------------------------- */

/*
 * Every decision to leave a flow alone AFTER FwpsAcquireWritableLayerDataPointer0 has
 * done its work is the same four steps: apply the layer data back unchanged, say PERMIT,
 * give FWPS_RIGHT_ACTION_WRITE back to the rest of the filter stack, release the handle.
 * The acquire clears that right and forces the action to BLOCK, so a path that omits the
 * restore drops the connection while looking completely healthy. One helper, because a
 * fourth copy-paste of those four lines is a fourth chance to forget one.
 */
static
VOID
TpdrvPermitUnchanged(
    _In_ UINT64 ClassifyHandle,
    _Inout_ PVOID WritableLayerData,
    _Inout_ FWPS_CLASSIFY_OUT0* ClassifyOut
    )
{
    FwpsApplyModifiedLayerData0(ClassifyHandle, WritableLayerData, 0);
    ClassifyOut->actionType = FWP_ACTION_PERMIT;
    ClassifyOut->rights |= FWPS_RIGHT_ACTION_WRITE;
    FwpsReleaseClassifyHandle0(ClassifyHandle);
}

VOID
NTAPI
TpdrvClassify(
    _In_ const FWPS_INCOMING_VALUES0* InFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
    _Inout_ VOID* LayerData,
    _In_ const void* ClassifyContext,
    _In_ const FWPS_FILTER1* Filter,
    _In_ UINT64 FlowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* ClassifyOut
    )
{
    UINT64 classifyHandle = 0;
    FWPS_CONNECT_REQUEST0* connectRequest = NULL;   /* fwpsk.h defines no P- typedef */
    PTP_FLOW_RECORD record = NULL;
    TP_FLOW_RECORD udpRecord;
    FWPS_CONNECTION_REDIRECT_STATE state;
    UINT16 tokenPort;
    ULONG proto = 0;
    BOOLEAN isUdp = FALSE;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(FlowContext);

    ClassifyOut->actionType = FWP_ACTION_PERMIT;

    if (LayerData == NULL)
    {
        return;
    }

    /*
     * Anti-loop, and the shape of this call is easy to get wrong: it takes the
     * REDIRECT RECORDS handle that the ALE metadata carries for this flow (not the
     * classify handle), it RETURNS the state rather than returning an NTSTATUS with
     * an out-parameter, and its states are enumeration values, not bit flags.
     *
     *   REDIRECTED_BY_SELF / PREVIOUSLY_REDIRECTED_BY_SELF -> must not redirect
     *     again, or our own proxy egress loops forever
     *   REDIRECTED_BY_OTHER                               -> we may still proxy
     */
    /*
     * From the WFP sampler's redirect callout: the whole redirect body runs only while
     * FWPS_RIGHT_ACTION_WRITE is set. An earlier callout may have cleared it, and
     * pushing on regardless is exactly how filter products stop coexisting.
     */
    if (!(ClassifyOut->rights & FWPS_RIGHT_ACTION_WRITE))
    {
        return;
    }

    /*
     * Absent redirect-records metadata means "not redirected" and we continue — the
     * sampler treats it that way; refusing here would silently disable the route on
     * any build where the field is not indicated.
     */
    state = FWPS_CONNECTION_NOT_REDIRECTED;
    if (FWPS_IS_METADATA_FIELD_PRESENT(InMetaValues, FWPS_METADATA_FIELD_REDIRECT_RECORD_HANDLE))
    {
        state = FwpsQueryConnectionRedirectState0(
            (HANDLE)InMetaValues->redirectRecords, g_RedirectHandle, NULL);
    }
    switch (state)
    {
    case FWPS_CONNECTION_REDIRECTED_BY_SELF:
        /* our own proxied egress: let it through untouched */
        ClassifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    case FWPS_CONNECTION_PREVIOUSLY_REDIRECTED_BY_SELF:
        /* the last redirection wins: change nothing, keep the current action */
        return;
    default:
        break;      /* NOT_REDIRECTED / REDIRECTED_BY_OTHER → go ahead and proxy */
    }

    /*
     * The protocol decides WHICH token pool to draw from (UDP needs one of its own),
     * so read it from the incoming values BEFORE reserving anything. IP_PROTOCOL is a
     * field the connect-redirect layers always indicate (fwpsu.h numbers it 5 in both
     * the V4 and V6 enums), which is why there is no run-time bounds test against the
     * value-count member here: naming one more kernel struct member by hand would be a
     * larger risk than the check it buys.
     */
    /*
     * The protocol field is indicated as FWP_UINT8, so read the union member that
     * matches. FWP_VALUE0's 64-bit case is `UINT64 *uint64` — a POINTER, not a value —
     * so "just take the wide one" would have dereferenced a byte count as an address.
     * (Found by compiling against the real fwptypes.h, 2026-11-25.)
     */
    /*
     * Read the member that matches what the engine actually indicated. At these layers
     * IP_PROTOCOL is FWP_UINT8 (and index 5 is
     * FWPS_FIELD_ALE_CONNECT_REDIRECT_V4/V6_IP_PROTOCOL — both checked against
     * Windows Kits/10/Include/10.0.26100.0/um/fwpsu.h on 2026-11-25), but guessing from
     * a single type is how the earlier draft asked for a member that does not exist:
     * FWP_VALUE0's 64-bit case is `UINT64 *uint64`, a POINTER, so a careless wide read
     * would dereference a byte count as an address at DISPATCH_LEVEL.
     */
    {
        const FWP_VALUE0* v = &InFixedValues->incomingValue[TP_FIELD_IP_PROTOCOL].value;
        switch (v->type)
        {
        case FWP_UINT8:  proto = v->uint8;                             break;
        case FWP_UINT16: proto = v->uint16;                            break;
        case FWP_UINT32: proto = v->uint32;                            break;
        case FWP_UINT64: proto = (v->uint64 != NULL) ? (ULONG)*v->uint64 : 0; break;
        default:         proto = 0;   /* FWP_EMPTY or unforeseen: not a transport */
        }
    }

    /*
     * Only transports this engine can carry. Redirecting ICMP/GRE/ESP would deliver
     * those packets to a TCP or UDP token listener — a redirect that BREAKS a flow that
     * was working — so permit and leave it to the rest of the stack, which is also what
     * the driverless hook does. Reference: trans_proxier::wfp_callout_plan::plan().
     */
    if (proto != IPPROTO_TCP && proto != IPPROTO_UDP)
    {
        ClassifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    }

    if (!FWPS_IS_METADATA_FIELD_PRESENT(InMetaValues, FWPS_METADATA_FIELD_PROCESS_ID))
    {
        return;                     /* no owning process ⇒ cannot attribute the flow */
    }

    isUdp = (proto == IPPROTO_UDP);

    status = FwpsAcquireClassifyHandle0((PVOID)ClassifyContext, 0, &classifyHandle);
    if (!NT_SUCCESS(status))
    {
        return;
    }

    /* second parameter is the FILTER id, not the redirect handle */
    status = FwpsAcquireWritableLayerDataPointer0(classifyHandle,
                                                 Filter->filterId,
                                                 0,
                                                 (PVOID*)&connectRequest,
                                                 ClassifyOut);
    if (!NT_SUCCESS(status) || connectRequest == NULL)
    {
        FwpsReleaseClassifyHandle0(classifyHandle);
        return;
    }

    /*
     * From here the engine has forced classifyOut->actionType to FWP_ACTION_BLOCK
     * and cleared FWPS_RIGHT_ACTION_WRITE. Every exit below must restore PERMIT
     * explicitly, or the connection is silently dropped.
     */
    if (TpdrvIsLoopbackRemote(&connectRequest->remoteAddressAndPort))
    {
        /* Microsoft: a connection to a local proxy must not be redirected */
        TpdrvPermitUnchanged(classifyHandle, (PVOID)connectRequest, ClassifyOut);
        return;
    }

    /*
     * The second half of the documented anti-loop recipe. ALE_CONNECT_REDIRECT can be
     * reached with a connection that ANOTHER callout has already redirected locally,
     * which is visible as a previousVersion carrying a localRedirectHandle of its own;
     * stacking a second local redirect on top of it is how two proxy products deadlock
     * each other. So permit, and leave the other product's redirect standing. (Microsoft's
     * snippet applies with FWPS_CLASSIFY_FLAG_REAUTHORIZE_IF_MODIFIED_BY_OTHERS; we have
     * changed nothing, so we must not ask the engine to reauthorize it.)
     */
    if (connectRequest->previousVersion != NULL &&
        connectRequest->previousVersion->localRedirectHandle != NULL &&
        connectRequest->previousVersion->modifierFilterId != Filter->filterId)
    {
        /*
         * Exactly Microsoft's snippet from "Using Bind or Connect Redirection": permit,
         * and ask the engine to reauthorize the flow if the OTHER product's redirect
         * turns out to matter, rather than silently leaving it. fwpsk.h spells the flag
         * FWPS_CLASSIFY_FLAG_REAUTHORIZE_IF_MODIFIED_BY_OTHERS = 0x00000001.
         */
        FwpsApplyModifiedLayerData0(classifyHandle, (PVOID)connectRequest,
                                   FWPS_CLASSIFY_FLAG_REAUTHORIZE_IF_MODIFIED_BY_OTHERS);
        ClassifyOut->actionType = FWP_ACTION_PERMIT;
        ClassifyOut->rights |= FWPS_RIGHT_ACTION_WRITE;
        FwpsReleaseClassifyHandle0(classifyHandle);
        return;
    }

    /*
     * The listener is chosen only now, because every path above that decided to permit
     * must leave the pools untouched — and a UDP reservation cannot be made before the
     * original 4-tuple is readable from the writable layer data. UDP needs a
     * RESERVATION rather than a port: the service cannot ask a datagram socket for its
     * redirect context, so the driver keeps the mapping until flowDelete returns the
     * token (that pairing is what makes the pool reusable). TCP shares one listener per
     * pool slot safely, since each accepted socket carries its own context.
     */
    if (isUdp)
    {
        tokenPort = TpdrvUdpReserve(
                    FWPS_IS_METADATA_FIELD_PRESENT(InMetaValues, FWPS_METADATA_FIELD_FLOW_HANDLE)
                        ? InMetaValues->flowHandle : 0,
                    &connectRequest->remoteAddressAndPort,
                    &connectRequest->localAddressAndPort,
                    proto,
                    (ULONG)InMetaValues->processId,
                    &udpRecord);
        if (tokenPort == 0)
        {
            /* table full: undo nothing, apply unchanged, and permit the flow */
            TpdrvPermitUnchanged(classifyHandle, (PVOID)connectRequest, ClassifyOut);
            return;
        }
    }
    else
    {
        tokenPort = TpdrvTakeToken(FALSE);
        if (tokenPort == 0)
        {
            /* no listener configured: permit rather than black-hole */
            TpdrvPermitUnchanged(classifyHandle, (PVOID)connectRequest, ClassifyOut);
            return;
        }
    }

    record = (PTP_FLOW_RECORD)TPDRV_ALLOC(sizeof(TP_FLOW_RECORD));
    if (record == NULL)
    {
        if (isUdp)
        {
            TpdrvUdpReleaseByFlow(tokenPort);
        }
        TpdrvPermitUnchanged(classifyHandle, (PVOID)connectRequest, ClassifyOut);
        return;
    }

    if (isUdp)
    {
        *record = udpRecord;      /* the table copy is authoritative for UDP */
    }
    else
    {
        TpdrvBuildRecord(record,
                         &connectRequest->remoteAddressAndPort,
                         &connectRequest->localAddressAndPort,
                         proto,
                         (ULONG)InMetaValues->processId,
                         tokenPort);
    }

    if (isUdp)
    {
        /*
         * Associate the token with the flow BEFORE the redirect is committed, because
         * this is the last point at which a failure can still be backed out of cleanly.
         * (flowHandle, layerId, calloutId, context): the flow handle comes from the
         * metadata and the callout id is the one FwpsCalloutRegister1 returned. Ignoring
         * the result — which an earlier draft did with `(void)` — leaks the slot for the
         * life of the driver: flowDelete only runs for flows that carry a context, so a
         * refused association means the token is never returned, and UDP redirection
         * stops dead after TPDRV_MAX_TOKENS flows while looking like a network fault.
         */
        NTSTATUS assoc = STATUS_UNSUCCESSFUL;
        if (!FWPS_IS_METADATA_FIELD_PRESENT(InMetaValues, FWPS_METADATA_FIELD_FLOW_HANDLE))
        {
            /* no flow handle ⇒ no context ⇒ flowDeleteFn never runs ⇒ the token would
             * be lost. Leave the datagram direct (which leaks nothing but is also
             * invisible) and COUNT it, so --verify can say why UDP is not proxied. */
            TpdrvNoteUdpUntrackable();
        }
        else
        {
            assoc = FwpsFlowAssociateContext0(InMetaValues->flowHandle,
                                              InFixedValues->layerId,
                                              g_CalloutId,
                                              (UINT64)tokenPort);
        }
        if (!NT_SUCCESS(assoc))
        {
            TpdrvUdpReleaseByFlow(tokenPort);
            ExFreePoolWithTag(record, TPDRV_POOL_TAG);
            TpdrvPermitUnchanged(classifyHandle, (PVOID)connectRequest, ClassifyOut);
            return;
        }
    }

    /*
     * Ownership transfers here: as WFPSampler's own comment says, WFP takes this memory
     * and frees it when the flow/redirect terminates, so TpdrvFlowDelete must NOT free
     * it — doing that is a pool double-free at IRQL 2, not a leak.
     */

    TpdrvSetRedirectTarget(&connectRequest->remoteAddressAndPort, tokenPort);
    /* all three are required for a loopback redirect to be accepted by the engine */
    connectRequest->localRedirectTargetPID = TpdrvProxyPid();
    connectRequest->localRedirectHandle = g_RedirectHandle;
    connectRequest->localRedirectContext = record;
    connectRequest->localRedirectContextSize = sizeof(TP_FLOW_RECORD);
    record = NULL;    /* WFP takes ownership and frees it with the flow */

    /*
     * fwpsk.h declares this `void`: the engine cannot refuse an apply, so there is no
     * status to inspect and nothing to roll back. Which is exactly why restoring
     * classifyOut->actionType below is mandatory on this path — the acquire left it at
     * BLOCK, and no return value will ever tell us we forgot.
     */
    FwpsApplyModifiedLayerData0(classifyHandle, (PVOID)connectRequest, 0);
    /* a redirect callout returns PERMIT: the redirect already happened in the data */
    ClassifyOut->actionType = FWP_ACTION_PERMIT;
    FwpsReleaseClassifyHandle0(classifyHandle);
    return;
}

/*
 * Note the boundary between this file and the Rust spec: the driver only ever
 * obtains the anti-loop answer from the ALE redirect-records metadata handle, and
 * `FlowFacts.redirected_by_self` in trans_proxier::wfp_callout_plan is where that
 * input is modelled and tested.
 */

/*
 * notifyFn1 — the documented shape is THREE parameters and an NTSTATUS:
 *
 *     NTSTATUS f(FWPS_CALLOUT_NOTIFY_TYPE notifyType,
 *                const GUID *filterKey,
 *                FWPS_FILTER1 *filter)
 *
 * The earlier draft of this function took (type, filter, flowContext) and returned VOID.
 * C accepts that mismatch into a function-pointer member with at most a warning, and the
 * filter engine then hands a GUID* to code that dereferences it as a filter — a bad
 * pointer at DISPATCH_LEVEL, not a build failure. Pinning the shape here is the whole
 * point of the comment.
 *
 * Returning anything but STATUS_SUCCESS for FWPS_CALLOUT_NOTIFY_ADD_FILTER makes the
 * engine refuse the add, i.e. refuse the service's own route. This driver has no per-flow
 * policy to validate (whitelisting is expressed as filters — see README), so the correct
 * answer to every notification, including ones it does not recognise, is success.
 */
NTSTATUS
NTAPI
TpdrvNotify(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE NotifyType,
    _In_ const GUID* FilterKey,
    _In_ FWPS_FILTER1* Filter
    )
{
    UNREFERENCED_PARAMETER(NotifyType);
    UNREFERENCED_PARAMETER(FilterKey);
    UNREFERENCED_PARAMETER(Filter);
    return STATUS_SUCCESS;
}

/*
 * The flow-delete callback's real shape (from "Registering Callouts with the Filter
 * Engine"): three scalars, and the flowContext is whatever the classify callback
 * associated with FwpsFlowAssociateContext0. There is no argument structure.
 */
VOID
NTAPI
TpdrvFlowDelete(
    _In_ UINT16 LayerId,
    _In_ UINT32 CalloutId,
    _In_ UINT64 FlowContext
    )
{
    UNREFERENCED_PARAMETER(LayerId);
    UNREFERENCED_PARAMETER(CalloutId);

    /*
     * The token a UDP flow was given comes back here. TpdrvClassify associates it with
     * FwpsFlowAssociateContext0, which is what makes this callback actionable — without
     * the pairing the pool leaks and UDP redirection stops working after
     * TPDRV_MAX_TOKENS flows, failing like a network problem rather than a driver bug.
     */
    if (FlowContext != 0)
    {
        TpdrvUdpReleaseByFlow((UINT16)FlowContext);
    }
}

#ifndef TPDRV_HOST_TEST
/* Everything from here down needs the I/O manager: a device object, IRP dispatch and
 * DriverEntry. The host test compiles it out rather than against fakes, because a
 * faked IoCreateDevice could only ever agree with itself. */

/* --- control device -------------------------------------------------------- */

static NTSTATUS
NTAPI
TpdrvIoctl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    )
{
    PIO_STACK_LOCATION sp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_SUCCESS;
    SIZE_T outLen = 0;
    PVOID buf = Irp->AssociatedIrp.SystemBuffer;
    ULONG inLen = sp->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outLenReq = sp->Parameters.DeviceIoControl.OutputBufferLength;

    UNREFERENCED_PARAMETER(DeviceObject);

    switch (sp->Parameters.DeviceIoControl.IoControlCode)
    {
    case IOCTL_TPDRV_SET_CONFIG:
    {
        PTPDRV_CONFIG c;
        if (inLen < UFIELD_OFFSET(TPDRV_CONFIG, Tokens) || buf == NULL)
        {
            status = STATUS_INVALID_BUFFER_SIZE;
            break;
        }
        c = (PTPDRV_CONFIG)buf;
        /*
         * One predicate, covering BOTH token arrays: bounding only the TCP array let a
         * caller claim 64 UDP tokens with a 16-byte buffer and have the driver read past
         * the end of it into the UDP pool. Validated before any of it is copied.
         */
        if (!TpdrvConfigBufferOk(inLen, c->TokenCount, c->UdpTokenCount))
        {
            KdPrint(("tpdrv_wfp: SET_CONFIG buffer too small (in=%lu tcp=%lu udp=%lu)\n",
                     inLen, c->TokenCount, c->UdpTokenCount));
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        {
            /*
             * The owner is whoever the KERNEL says opened this handle, never whatever the
             * request claims — a caller that lies about its pid is refused rather than
             * trusted. See record.h's rule.
             */
            ULONG caller = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
            ULONG owner = TpdrvProxyPid();
            if (!TpdrvConfigMayBeSetBy(caller, owner))
            {
                KdPrint(("tpdrv_wfp: SET_CONFIG from pid %lu REFUSED (claim held by %lu)\n",
                         caller, owner));
                status = STATUS_PRIVILEGE_NOT_HELD;
                break;
            }
            if (c->ProxyPid != caller)
            {
                /* not an attack on the claim (it is refused by that anyway) but the
                 * service and the driver have disagreeing views: refuse the mismatch */
                status = STATUS_INVALID_PARAMETER;
                break;
            }
            TpdrvApplyConfig(caller, c->Enabled, c->Tokens, c->TokenCount,
                               c->UdpTokens, c->UdpTokenCount);
        }
        KdPrint(("tpdrv_wfp: config pid=%lu tokens=%lu enabled=%lu\n",
                 c->ProxyPid, c->TokenCount, c->Enabled));
        break;
    }

    case IOCTL_TPDRV_GET_STATUS:
    {
        PTPDRV_STATUS st;
        if (outLenReq < sizeof(TPDRV_STATUS) || buf == NULL)
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        st = (PTPDRV_STATUS)buf;
        st->Enabled = TpdrvEnabled();
        st->ProxyPid = TpdrvProxyPid();
        st->TokenCount = TpdrvTokenCount();
        st->UdpTokenCount = TpdrvUdpTokenCount();
        st->UdpActiveFlows = TpdrvUdpActiveFlows();
        st->CalloutsRegistered = (ULONG)g_CalloutRegistered;
        st->RedirectHandleValid = (g_RedirectHandle != NULL) ? 1UL : 0UL;
        st->UdpUntrackable = TpdrvUdpUntrackable();
        outLen = sizeof(TPDRV_STATUS);
        break;
    }

    case IOCTL_TPDRV_QUERY_FLOW:
    {
        /* the service asks: which flow arrived on this token port? */
        PTP_FLOW_RECORD out;
        UINT16 port;
        if (inLen < sizeof(UINT16) || outLenReq < sizeof(TP_FLOW_RECORD) || buf == NULL)
        {
            status = STATUS_INVALID_BUFFER_SIZE;
            break;
        }
        {
            ULONG caller = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
            if (!TpdrvMayQueryFlow(caller, TpdrvProxyPid()))
            {
                /* the record names another process's destination and pid */
                status = STATUS_PRIVILEGE_NOT_HELD;
                break;
            }
        }
        port = *(PUINT16)buf;
        out = (PTP_FLOW_RECORD)buf;
        if (!TpdrvUdpLookup(port, out))
        {
            status = STATUS_NOT_FOUND;
            break;
        }
        outLen = sizeof(TP_FLOW_RECORD);
        break;
    }

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = outLen;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

static NTSTATUS
NTAPI
TpdrvPassThrough(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    )
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

/* --- entry / unload -------------------------------------------------------- */

VOID
NTAPI
TpdrvUnload(
    _In_ PDRIVER_OBJECT DriverObject
    )
{
    UNICODE_STRING link;

    if (g_CalloutRegistered)
    {
        FwpsCalloutUnregisterById0(g_CalloutId);
        g_CalloutRegistered = 0;
    }
    if (g_RedirectHandle != NULL)
    {
        FwpsRedirectHandleDestroy0(g_RedirectHandle);
        g_RedirectHandle = NULL;
    }
    TpdrvApplyConfig(0, 0, NULL, 0, NULL, 0);

    RtlInitUnicodeString(&link, NTDOS_DEVICE_NAME);
    IoDeleteSymbolicLink(&link);
    if (g_DeviceObject != NULL)
    {
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
    }
    UNREFERENCED_PARAMETER(DriverObject);
}

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    UNICODE_STRING deviceName;
    UNICODE_STRING linkName;
    FWPS_CALLOUT1 callout;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(RegistryPath);

    RtlInitUnicodeString(&deviceName, NT_DEVICE_NAME);
    RtlInitUnicodeString(&linkName, NTDOS_DEVICE_NAME);

    status = IoCreateDevice(DriverObject,
                            0,
                            &deviceName,
                            FILE_DEVICE_UNKNOWN,
                            FILE_DEVICE_SECURE_OPEN,
                            FALSE,
                            &g_DeviceObject);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    status = IoCreateSymbolicLink(&linkName, &deviceName);
    if (!NT_SUCCESS(status))
    {
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
        return status;
    }

    DriverObject->DriverUnload = TpdrvUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = TpdrvPassThrough;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = TpdrvPassThrough;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = TpdrvIoctl;

    status = FwpsRedirectHandleCreate0(&g_ProviderKey, 0, &g_RedirectHandle);
    if (!NT_SUCCESS(status))
    {
        goto fail;
    }

    /*
     * Register1, not Register0: the redirect layers are only served by classifyFn1
     * or later. The matching callout OBJECT (same key, per layer) is added by the
     * service with FwpmCalloutAdd0 — see Wfp::ensure_callout — before it installs any
     * filter that names this key.
     */
    RtlZeroMemory(&callout, sizeof(callout));
    callout.calloutKey = g_CalloutKey;
    callout.flags = 0;
    callout.classifyFn = TpdrvClassify;
    callout.notifyFn = TpdrvNotify;
    callout.flowDeleteFn = TpdrvFlowDelete;

    status = FwpsCalloutRegister1(g_DeviceObject, &callout, &g_CalloutId);
    if (!NT_SUCCESS(status))
    {
        goto fail;
    }
    g_CalloutRegistered = 1;

    /* stay disabled until the service pushes tokens + its pid */
    TpdrvApplyConfig(0, 0, NULL, 0, NULL, 0);
    KdPrint(("tpdrv_wfp: loaded, callout id %lu (disabled until configured)\n", g_CalloutId));
    return STATUS_SUCCESS;

fail:
    if (g_RedirectHandle != NULL)
    {
        FwpsRedirectHandleDestroy0(g_RedirectHandle);
        g_RedirectHandle = NULL;
    }
    IoDeleteSymbolicLink(&linkName);
    if (g_DeviceObject != NULL)
    {
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
    }
    return status;
}

#endif /* TPDRV_HOST_TEST */

/*
 * The contract with the Rust side. A mismatch here means the proxy would decode a
 * wrong destination, so the build fails instead.
 */
C_ASSERT(sizeof(TP_FLOW_RECORD) == 72);
C_ASSERT(FIELD_OFFSET(TP_FLOW_RECORD, family) == 4);
C_ASSERT(FIELD_OFFSET(TP_FLOW_RECORD, portBe) == 6);
C_ASSERT(FIELD_OFFSET(TP_FLOW_RECORD, addr) == 8);
C_ASSERT(FIELD_OFFSET(TP_FLOW_RECORD, pid) == 24);
C_ASSERT(FIELD_OFFSET(TP_FLOW_RECORD, chain) == 28);
C_ASSERT(FIELD_OFFSET(TP_FLOW_RECORD, verdict) == 32);
C_ASSERT(FIELD_OFFSET(TP_FLOW_RECORD, proto) == 33);
C_ASSERT(FIELD_OFFSET(TP_FLOW_RECORD, tokenPort) == 34);
C_ASSERT(FIELD_OFFSET(TP_FLOW_RECORD, flowId) == 40);
C_ASSERT(FIELD_OFFSET(TP_FLOW_RECORD, localAddr) == 48);
C_ASSERT(FIELD_OFFSET(TP_FLOW_RECORD, localPortBe) == 64);
