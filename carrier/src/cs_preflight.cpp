// Offline PE32 preflight for the OS-loader/DxWnd route.  Zero VirtualSize is
// reported as metadata, not treated as a mapper failure: PF pe_image.hpp
// copies SizeOfRawData into the nonzero OptionalHeader SizeOfImage reservation.
#include <windows.h>
#include <cstdio>
#include <vector>

int main(int argc, char** argv) {
    if (argc != 2) { fprintf(stderr, "usage: cs_preflight IMAGE.EXE\n"); return 2; }
    FILE* file = nullptr;
    fopen_s(&file, argv[1], "rb");
    if (!file) { fprintf(stderr, "cannot open %s\n", argv[1]); return 2; }
    if (fseek(file, 0, SEEK_END) != 0) { fclose(file); return 2; }
    long length = ftell(file);
    if (length < (long)sizeof(IMAGE_DOS_HEADER) || fseek(file, 0, SEEK_SET) != 0) {
        fclose(file); fprintf(stderr, "truncated DOS header\n"); return 2;
    }
    std::vector<unsigned char> bytes((size_t)length);
    const bool read_ok = fread(bytes.data(), 1, bytes.size(), file) == bytes.size();
    fclose(file);
    if (!read_ok) return 2;
    const IMAGE_DOS_HEADER* dos = (const IMAGE_DOS_HEADER*)bytes.data();
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) { fprintf(stderr, "not MZ\n"); return 2; }
    if (dos->e_lfanew < 0 || (size_t)dos->e_lfanew > bytes.size() ||
        bytes.size() - (size_t)dos->e_lfanew < sizeof(IMAGE_NT_HEADERS32)) {
        fprintf(stderr, "truncated NT header\n"); return 2;
    }
    const IMAGE_NT_HEADERS32* nt = (const IMAGE_NT_HEADERS32*)(bytes.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC ||
        nt->FileHeader.Machine != IMAGE_FILE_MACHINE_I386 ||
        nt->FileHeader.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER32)) {
        fprintf(stderr, "not PE32\n"); return 2;
    }
    const size_t section_offset = (size_t)dos->e_lfanew + sizeof(DWORD) +
        sizeof(IMAGE_FILE_HEADER) + nt->FileHeader.SizeOfOptionalHeader;
    if (section_offset > bytes.size() || nt->FileHeader.NumberOfSections >
        (bytes.size() - section_offset) / sizeof(IMAGE_SECTION_HEADER)) {
        fprintf(stderr, "truncated section table\n"); return 2;
    }
    printf("image_base=0x%08lX size_of_image=0x%08lX entry_rva=0x%08lX sections=%u\n",
           nt->OptionalHeader.ImageBase, nt->OptionalHeader.SizeOfImage,
           nt->OptionalHeader.AddressOfEntryPoint, nt->FileHeader.NumberOfSections);
    const IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(nt);
    bool zero_virtual_size = false;
    for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section) {
        char name[9] = {}; memcpy(name, section->Name, 8);
        printf("section=%s rva=0x%08lX virtual_size=0x%08lX raw_size=0x%08lX raw_offset=0x%08lX\n",
               name, section->VirtualAddress, section->Misc.VirtualSize,
               section->SizeOfRawData, section->PointerToRawData);
        if (section->Misc.VirtualSize == 0) zero_virtual_size = true;
    }
    printf("zero_virtual_size_present=%s\n", zero_virtual_size ? "true" : "false");
    printf("route_decision=OS-loaded CSTORM.EXE under DxWnd; manual mapper is not selected because it changes process/image identity\n");
    return 0;
}
