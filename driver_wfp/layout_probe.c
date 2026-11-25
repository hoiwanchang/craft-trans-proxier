/*
 * layout_probe.c — NOT part of the driver. Compiled alone (`cl /c /FA`) to force the
 * real fwpsk.h / fwptypes.h to answer, in the binary itself, for every layout fact that
 * tpdrv_wfp.c and the Rust spec assume. Two mechanisms, deliberately:
 *
 *   1. `TpLayoutProbe` is an initialised array of the quantities. The /Fa listing shows
 *      the emitted constants, so the numbers below are the compiler's, not arithmetic I
 *      did by hand (build.ps1 -Test greps them out and prints them next to the Rust side
 *      expectations).
 *   2. The C_ASSERTs then pin those numbers. If a future SDK reorders a struct, this file
 *      stops compiling — which is the only way a layout assumption can be tested without
 *      a kernel.
 *
 * The distinction that matters: the driver accesses these members BY NAME, so a reorder
 * cannot hurt it; what these assertions protect is the *documentation* of the shapes (and
 * `wdk_shim.h`, whose job is to be close enough to the real headers that `gcc
 * -fsyntax-only` remains a meaningful check on a machine without one).
 */

#include <ndis.h>
#include <fwpsk.h>
#include "record.h"

/* --- the numbers, as the compiler sees them -------------------------------- */
const UINT64 TpLayoutProbe[] = {
    sizeof(SOCKADDR_STORAGE),
    sizeof(SOCKADDR_IN),
    sizeof(SOCKADDR_IN6),
    sizeof(FWPS_CONNECT_REQUEST0),
    FIELD_OFFSET(FWPS_CONNECT_REQUEST0, remoteAddressAndPort),
    FIELD_OFFSET(FWPS_CONNECT_REQUEST0, localRedirectTargetPID),
    FIELD_OFFSET(FWPS_CONNECT_REQUEST0, localRedirectContext),
    FIELD_OFFSET(FWPS_CONNECT_REQUEST0, localRedirectContextSize),
    sizeof(FWP_VALUE0),
    FIELD_OFFSET(FWP_VALUE0, type),
    FIELD_OFFSET(FWP_VALUE0, uint64),
    sizeof(FWPS_CLASSIFY_OUT0),
    FIELD_OFFSET(FWPS_CLASSIFY_OUT0, actionType),
    FIELD_OFFSET(FWPS_CLASSIFY_OUT0, rights),
    sizeof(FWPS_INCOMING_METADATA_VALUES0),
    FIELD_OFFSET(FWPS_INCOMING_METADATA_VALUES0, currentMetadataValues),
    FIELD_OFFSET(FWPS_INCOMING_METADATA_VALUES0, processId),
    sizeof(TP_FLOW_RECORD),
    FIELD_OFFSET(TP_FLOW_RECORD, portBe),
    FIELD_OFFSET(TP_FLOW_RECORD, localPortBe),
};

/* --- and the claims, pinned ----------------------------------------------- */
/* The two sockaddr sizes the encoders in record.c write byte for byte. */
C_ASSERT(sizeof(SOCKADDR_STORAGE) == 128);
C_ASSERT(sizeof(SOCKADDR_IN) == 16);
C_ASSERT(sizeof(SOCKADDR_IN6) == 28);

/* FWPS_CONNECT_REQUEST0: both endpoints first, then the redirect fields. TpdrvClassify
 * rewrites remoteAddressAndPort in place and stashes the record in localRedirectContext,
 * so these are the offsets a reader of docs/WFP_ROADMAP.md will be told. */
C_ASSERT(FIELD_OFFSET(FWPS_CONNECT_REQUEST0, remoteAddressAndPort) == 128);
C_ASSERT(FIELD_OFFSET(FWPS_CONNECT_REQUEST0, localRedirectTargetPID) == 264);
C_ASSERT(FIELD_OFFSET(FWPS_CONNECT_REQUEST0, localRedirectContext) == 296);
C_ASSERT(sizeof(FWPS_CONNECT_REQUEST0) == 312);

/*
 * The one that would have been expensive: FWP_VALUE0's 64-bit case is `UINT64 *uint64`
 * — a pointer — and the type tag sits at offset 0, so `value.uint64Data` (what an
 * earlier draft wrote) names nothing, and reading the wide member as a value would
 * dereference a protocol number as an address at DISPATCH_LEVEL.
 */
C_ASSERT(FIELD_OFFSET(FWP_VALUE0, type) == 0);
C_ASSERT(FIELD_OFFSET(FWP_VALUE0, uint64) == 8);
C_ASSERT(sizeof(((FWP_VALUE0*)0)->uint64) == sizeof(void*));

/* rights is the field the acquire clears; actionType is the one it forces to BLOCK. */
C_ASSERT(FIELD_OFFSET(FWPS_CLASSIFY_OUT0, actionType) == 0);
C_ASSERT(FIELD_OFFSET(FWPS_CLASSIFY_OUT0, rights) == 24);

/* The metadata-presence mask the classify path gates every read behind. */
C_ASSERT(FWPS_METADATA_FIELD_FLOW_HANDLE == 0x00000002u);
C_ASSERT(FWPS_METADATA_FIELD_PROCESS_ID == 0x00000020u);
C_ASSERT(FWPS_METADATA_FIELD_REDIRECT_RECORD_HANDLE == 0x40000000u);
C_ASSERT(FWPS_RIGHT_ACTION_WRITE == 0x00000001u);

/*
 * The ALE field index the driver hardcodes, asserted from the platform's own enum rather
 * than from a documentation page. (build.ps1 also checks the V6 numbering.)
 */
C_ASSERT(FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_PROTOCOL == 5);

/* The 72-byte record the service decodes — same constant as the Rust side, same name. */
C_ASSERT(sizeof(TP_FLOW_RECORD) == 72);
C_ASSERT(FIELD_OFFSET(TP_FLOW_RECORD, portBe) == 6);
/* port octets are wire order at 6; the local port sits at 64 (see record.h) */
C_ASSERT(FIELD_OFFSET(TP_FLOW_RECORD, localPortBe) == 64);
