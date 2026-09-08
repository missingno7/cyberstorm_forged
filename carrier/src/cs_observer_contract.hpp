#pragma once
#include <windows.h>

inline bool cs_getproc_ordinal(ULONG_PTR value) {
    return (value >> 16) == 0;
}

inline WORD cs_import_ordinal(DWORD thunk_ordinal) {
    return IMAGE_ORDINAL32(thunk_ordinal);
}

inline bool cs_same_or_unset_forward(void* published, void* candidate) {
    return published == nullptr || published == candidate;
}

inline bool cs_rva_range(DWORD rva, SIZE_T length, DWORD image_size) {
    return rva <= image_size && length <= (SIZE_T)(image_size - rva);
}
