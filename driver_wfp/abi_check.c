/*
 * abi_check.c — independent verification of the WFP ABI mirrored in src/wfp.rs.
 *
 * The Rust control plane redeclares Microsoft's WFP structs because Rust cannot
 * consume the SDK headers. Those declarations were transcribed from
 *   Windows Kits/10/Include/10.0.26100.0/shared/{fwptypes,fwpmtypes}.idl
 *   Windows Kits/10/Include/10.0.26100.0/um/fwpmu.h
 * and pinned by Rust unit tests — but a transcription can only agree with itself.
 *
 * This file asks a C compiler what the REAL headers say. Any disagreement fails
 * the build, which means src/wfp.rs (and its `abi_mirrors_header_sizes_and_offsets`
 * test) has to be updated in the same change.
 *
 *   gcc driver_wfp/abi_check.c -o abi_check && ./abi_check        # or cl /Feabi_check
 *
 * Verified with gcc 16.2 against MinGW-w64's copies of the same headers; any
 * toolchain that ships fwpmu.h works, including the WDK's own when building the
 * driver. Prints the numbers it checked, so they land in a log or a PR.
 */
#include <windows.h>
#include <fwptypes.h>
#include <fwpmtypes.h>
#include <fwpmu.h>
#include <stddef.h>
#include <stdio.h>

/* Values asserted identically in src/wfp.rs (tests) — keep the two in step. */
_Static_assert(sizeof(GUID) == 16, "GUID");
_Static_assert(sizeof(FWP_VALUE0) == 16, "FWP_VALUE0");
_Static_assert(sizeof(FWP_CONDITION_VALUE0) == 16, "FWP_CONDITION_VALUE0");
_Static_assert(sizeof(FWP_BYTE_BLOB) == 16, "FWP_BYTE_BLOB (UINT32 size + pointer data)");
_Static_assert(sizeof(FWPM_DISPLAY_DATA0) == 16, "FWPM_DISPLAY_DATA0");
_Static_assert(sizeof(FWPM_FILTER_CONDITION0) == 40, "FWPM_FILTER_CONDITION0");
_Static_assert(offsetof(FWPM_FILTER_CONDITION0, conditionValue) == 24, "conditionValue@24");
_Static_assert(sizeof(FWPM_ACTION0) == 20, "FWPM_ACTION0 = type + GUID union, NO redirect field");
_Static_assert(offsetof(FWPM_ACTION0, calloutKey) == 4, "calloutKey@4");
_Static_assert(sizeof(FWPM_SUBLAYER0) == 72, "FWPM_SUBLAYER0");
_Static_assert(offsetof(FWPM_SUBLAYER0, weight) == 64, "sublayer weight (UINT16) @64");
_Static_assert(sizeof(FWPM_FILTER0) == 200, "FWPM_FILTER0");
_Static_assert(offsetof(FWPM_FILTER0, layerKey) == 64, "layerKey@64");
_Static_assert(offsetof(FWPM_FILTER0, subLayerKey) == 80, "subLayerKey@80");
_Static_assert(offsetof(FWPM_FILTER0, weight) == 96, "weight@96");
_Static_assert(offsetof(FWPM_FILTER0, numFilterConditions) == 112, "numFilterConditions@112");
_Static_assert(offsetof(FWPM_FILTER0, filterCondition) == 120, "filterCondition@120 (BEFORE action)");
_Static_assert(offsetof(FWPM_FILTER0, action) == 128, "action@128");
_Static_assert(offsetof(FWPM_FILTER0, filterId) == 176, "filterId@176");
_Static_assert(sizeof(FWPM_CALLOUT0) == 88, "FWPM_CALLOUT0");
_Static_assert(offsetof(FWPM_CALLOUT0, applicableLayer) == 64, "applicableLayer@64");
_Static_assert(offsetof(FWPM_CALLOUT0, calloutId) == 80, "calloutId@80");
_Static_assert(sizeof(FWPM_SESSION0) == 72, "FWPM_SESSION0");

/* enum values src/wfp.rs hard-codes */
_Static_assert(FWP_UINT8 == 1, "FWP_UINT8");
_Static_assert(FWP_UINT16 == 2, "FWP_UINT16");
_Static_assert(FWP_UINT32 == 3, "FWP_UINT32");
_Static_assert(FWP_UINT64 == 4, "FWP_UINT64");
_Static_assert(FWP_BYTE_BLOB_TYPE == 12, "FWP_BYTE_BLOB_TYPE");
_Static_assert(FWP_MATCH_EQUAL == 0, "FWP_MATCH_EQUAL");
_Static_assert(FWP_ACTION_BLOCK == 0x1001, "FWP_ACTION_BLOCK");
_Static_assert(FWP_ACTION_PERMIT == 0x1002, "FWP_ACTION_PERMIT");
_Static_assert(FWP_ACTION_CALLOUT_TERMINATING == 0x5003, "FWP_ACTION_CALLOUT_TERMINATING");
_Static_assert(FWP_ACTION_CALLOUT_INSPECTION == 0x6004, "FWP_ACTION_CALLOUT_INSPECTION");

/*
 * The premise this project is built on, asserted against the real header rather
 * than argued: a filter action is a type plus a GUID. There is nowhere in
 * FWPM_ACTION0 to put "redirect to 127.0.0.1:port", which is why per-app redirect
 * needs a callout driver and not just a filter.
 */
_Static_assert(sizeof(FWPM_ACTION0) == sizeof(FWP_ACTION_TYPE) + sizeof(GUID),
               "FWPM_ACTION0 carries only a GUID besides its type: filters cannot redirect");

int
main(void)
{
    printf("GUID=%zu FWP_VALUE0=%zu FWP_BYTE_BLOB=%zu FWPM_DISPLAY_DATA0=%zu\n",
           sizeof(GUID), sizeof(FWP_VALUE0), sizeof(FWP_BYTE_BLOB), sizeof(FWPM_DISPLAY_DATA0));
    printf("FWPM_FILTER_CONDITION0=%zu (conditionValue@%zu)\n",
           sizeof(FWPM_FILTER_CONDITION0), offsetof(FWPM_FILTER_CONDITION0, conditionValue));
    printf("FWPM_ACTION0=%zu (calloutKey@%zu)\n",
           sizeof(FWPM_ACTION0), offsetof(FWPM_ACTION0, calloutKey));
    printf("FWPM_SUBLAYER0=%zu (weight@%zu)\n",
           sizeof(FWPM_SUBLAYER0), offsetof(FWPM_SUBLAYER0, weight));
    printf("FWPM_FILTER0=%zu (layer@%zu sublayer@%zu weight@%zu ncond@%zu cond@%zu action@%zu id@%zu)\n",
           sizeof(FWPM_FILTER0), offsetof(FWPM_FILTER0, layerKey), offsetof(FWPM_FILTER0, subLayerKey),
           offsetof(FWPM_FILTER0, weight), offsetof(FWPM_FILTER0, numFilterConditions),
           offsetof(FWPM_FILTER0, filterCondition), offsetof(FWPM_FILTER0, action),
           offsetof(FWPM_FILTER0, filterId));
    printf("FWPM_CALLOUT0=%zu FWPM_SESSION0=%zu\n", sizeof(FWPM_CALLOUT0), sizeof(FWPM_SESSION0));
    printf("actions: PERMIT=0x%x BLOCK=0x%x CALLOUT_TERMINATING=0x%x CALLOUT_INSPECTION=0x%x\n",
           (unsigned)FWP_ACTION_PERMIT, (unsigned)FWP_ACTION_BLOCK,
           (unsigned)FWP_ACTION_CALLOUT_TERMINATING, (unsigned)FWP_ACTION_CALLOUT_INSPECTION);
    printf("types: UINT8=%u UINT16=%u UINT32=%u UINT64=%u BYTE_BLOB=%u MATCH_EQUAL=%u\n",
           (unsigned)FWP_UINT8, (unsigned)FWP_UINT16, (unsigned)FWP_UINT32,
           (unsigned)FWP_UINT64, (unsigned)FWP_BYTE_BLOB_TYPE, (unsigned)FWP_MATCH_EQUAL);
    printf("OK: every value asserted by src/wfp.rs matches these headers\n");
    return 0;
}
