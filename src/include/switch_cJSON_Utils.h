#include "switch.h"

#ifndef SWITCH_JSON_UTILS_H
#define SWITCH_JSON_UTILS_H 1
#include "switch_cJSON.h"

/* Implement RFC6901 (https://tools.ietf.org/html/rfc6901) JSON Pointer spec. */
SWITCH_DECLARE(cJSON *) cJSONUtils_GetPointer(cJSON *object, const char *pointer);

/* Implement RFC6902 (https://tools.ietf.org/html/rfc6902) JSON Patch spec. */
SWITCH_DECLARE(cJSON *) cJSONUtils_GeneratePatches(cJSON *from, cJSON *to);
/* Utility for generating patch array entries. */
SWITCH_DECLARE(void) cJSONUtils_AddPatchToArray(cJSON *array, const char *op, const char *path, cJSON *val);
/* Returns 0 for success. */
SWITCH_DECLARE(int) cJSONUtils_ApplyPatches(cJSON *object, cJSON *patches);

/*
// Note that ApplyPatches is NOT atomic on failure. To implement an atomic ApplyPatches, use:
//int cJSONUtils_AtomicApplyPatches(cJSON **object, cJSON *patches)
//{
//    cJSON *modme = cJSON_Duplicate(*object, 1);
//    int error = cJSONUtils_ApplyPatches(modme, patches);
//    if (!error)
//    {
//        cJSON_Delete(*object);
//        *object = modme;
//    }
//    else
//    {
//        cJSON_Delete(modme);
//    }
//
//    return error;
//}
// Code not added to library since this strategy is a LOT slower.
*/

/* Implement RFC7386 (https://tools.ietf.org/html/rfc7396) JSON Merge Patch spec. */
/* target will be modified by patch. return value is new ptr for target. */
SWITCH_DECLARE(cJSON *) cJSONUtils_MergePatch(cJSON *target, cJSON *patch);
/* generates a patch to move from -> to */
SWITCH_DECLARE(cJSON *) cJSONUtils_GenerateMergePatch(cJSON *from, cJSON *to);

/* Given a root object and a target object, construct a pointer from one to the other. */
SWITCH_DECLARE(char *) cJSONUtils_FindPointerFromObjectTo(cJSON *object, cJSON *target);

/* Sorts the members of the object into alphabetical order. */
SWITCH_DECLARE(void) cJSONUtils_SortObject(cJSON *object);

#endif // SWITCH_JSON_UTILS_H
