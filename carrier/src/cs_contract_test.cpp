#include <cstdio>
#include "cs_observer_contract.hpp"

int main() {
    const bool pass =
        cs_getproc_ordinal(5) &&
        !cs_getproc_ordinal(0x80000005UL) &&
        !cs_getproc_ordinal((ULONG_PTR)"GetProcAddress") &&
        cs_import_ordinal(IMAGE_ORDINAL_FLAG32 | 5) == 5 &&
        cs_same_or_unset_forward(nullptr, (void*)1) &&
        cs_same_or_unset_forward((void*)1, (void*)1) &&
        !cs_same_or_unset_forward((void*)1, (void*)2) &&
        cs_rva_range(0, 0, 16) &&
        cs_rva_range(15, 1, 16) &&
        !cs_rva_range(16, 1, 16);
    std::printf("observer_contract=%s\n", pass ? "PASS" : "FAIL");
    return pass ? 0 : 1;
}
