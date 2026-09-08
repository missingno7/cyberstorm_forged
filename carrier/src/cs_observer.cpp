// CyberStorm chain-forward observer DLL.  It is designed to be loaded into
// the OS-loaded CSTORM.EXE process after DxWnd owns that launch. It neither
// maps the guest image nor supplies fake imports: selected existing IAT
// targets are observed only by forwarding to the target DxWnd installed.
#include <windows.h>
#include <tlhelp32.h>
#include <cstdio>
#include <cstdarg>
#include <cstring>
#include "cs_observer_contract.hpp"

static HANDLE g_log = INVALID_HANDLE_VALUE;
typedef HMODULE (WINAPI *LoadLibraryAType)(LPCSTR);
typedef HMODULE (WINAPI *LoadLibraryWType)(LPCWSTR);
typedef HMODULE (WINAPI *LoadLibraryExAType)(LPCSTR, HANDLE, DWORD);
typedef HMODULE (WINAPI *LoadLibraryExWType)(LPCWSTR, HANDLE, DWORD);
typedef FARPROC (WINAPI *GetProcAddressType)(HMODULE, LPCSTR);
static LoadLibraryAType g_load_library_a = nullptr;
static LoadLibraryWType g_load_library_w = nullptr;
static LoadLibraryExAType g_load_library_ex_a = nullptr;
static LoadLibraryExWType g_load_library_ex_w = nullptr;
static GetProcAddressType g_get_proc_address = nullptr;
static CRITICAL_SECTION g_log_lock;
static bool g_log_lock_ready = false;
static DWORD g_hooks_installed = 0;

static void log_line(const char* format, ...);

static void log_process_provenance() {
    char image[MAX_PATH] = {};
    char directory[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, image, sizeof(image));
    GetCurrentDirectoryA(sizeof(directory), directory);
    log_line("process image=%s current_directory=%s", image, directory);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
                                                GetCurrentProcessId());
    if (snapshot == INVALID_HANDLE_VALUE) {
        log_line("loaded_modules unavailable gle=%lu", GetLastError());
        return;
    }
    MODULEENTRY32 entry = {};
    entry.dwSize = sizeof(entry);
    if (!Module32First(snapshot, &entry)) {
        log_line("loaded_modules unavailable gle=%lu", GetLastError());
    } else {
        do {
            log_line("loaded_module path=%s base=%p size=0x%08lX", entry.szExePath,
                     entry.modBaseAddr, entry.modBaseSize);
        } while (Module32Next(snapshot, &entry));
    }
    CloseHandle(snapshot);
}

static BOOL CALLBACK log_owned_window(HWND window, LPARAM label) {
    DWORD process_id = 0;
    GetWindowThreadProcessId(window, &process_id);
    if (process_id != GetCurrentProcessId()) return TRUE;
    char title[256] = "";
    RECT client = {};
    GetWindowTextA(window, title, sizeof(title));
    GetClientRect(window, &client);
    log_line("window sample=%s hwnd=%p title=%s style=0x%08lX exstyle=0x%08lX client=%ldx%ld",
             (const char*)label, window, title, (unsigned long)GetWindowLongA(window, GWL_STYLE),
             (unsigned long)GetWindowLongA(window, GWL_EXSTYLE),
             client.right - client.left, client.bottom - client.top);
    return TRUE;
}

static void log_passive_display_sample(const char* label) {
    DEVMODEA mode = {};
    mode.dmSize = sizeof(mode);
    if (EnumDisplaySettingsA(nullptr, ENUM_CURRENT_SETTINGS, &mode)) {
        log_line("display sample=%s width=%lu height=%lu bpp=%lu hz=%lu",
                 label, mode.dmPelsWidth, mode.dmPelsHeight, mode.dmBitsPerPel, mode.dmDisplayFrequency);
    } else {
        log_line("display sample=%s unavailable gle=%lu", label, GetLastError());
    }
    EnumWindows(log_owned_window, (LPARAM)label);
}

static void log_line(const char* format, ...) {
    if (g_log == INVALID_HANDLE_VALUE) return;
    char buffer[1024];
    va_list args;
    va_start(args, format);
    int n = _vsnprintf_s(buffer, sizeof(buffer), _TRUNCATE, format, args);
    va_end(args);
    if (n < 0) n = (int)strlen(buffer);
    if (n > (int)sizeof(buffer) - 3) n = (int)sizeof(buffer) - 3;
    buffer[n++] = '\r';
    buffer[n++] = '\n';
    if (g_log_lock_ready) EnterCriticalSection(&g_log_lock);
    DWORD written = 0;
    WriteFile(g_log, buffer, (DWORD)n, &written, nullptr);
    if (g_log_lock_ready) LeaveCriticalSection(&g_log_lock);
}

static const char* name_or_ordinal(const void* value, char* out, size_t out_size) {
    ULONG_PTR raw = (ULONG_PTR)value;
    // GetProcAddress uses a low-word ordinal pointer, unlike an import thunk
    // whose ordinal is marked with IMAGE_ORDINAL_FLAG32 in its high bit.
    if (cs_getproc_ordinal(raw)) {
        _snprintf_s(out, out_size, _TRUNCATE, "#%u", (unsigned)raw);
        return out;
    }
    return (const char*)value;
}

extern "C" HMODULE WINAPI observe_LoadLibraryA(LPCSTR path) {
    HMODULE result = g_load_library_a(path);
    DWORD error = GetLastError();
    log_line("LoadLibraryA path=%s result=%p gle=%lu", path ? path : "<null>", result, error);
    SetLastError(error);
    return result;
}

extern "C" HMODULE WINAPI observe_LoadLibraryW(LPCWSTR path) {
    HMODULE result = g_load_library_w(path);
    DWORD error = GetLastError();
    log_line("LoadLibraryW path=%p result=%p gle=%lu", path, result, error);
    SetLastError(error);
    return result;
}

extern "C" HMODULE WINAPI observe_LoadLibraryExA(LPCSTR path, HANDLE file, DWORD flags) {
    HMODULE result = g_load_library_ex_a(path, file, flags);
    DWORD error = GetLastError();
    log_line("LoadLibraryExA path=%s file=%p flags=0x%08lX result=%p gle=%lu",
             path ? path : "<null>", file, flags, result, error);
    SetLastError(error);
    return result;
}

extern "C" HMODULE WINAPI observe_LoadLibraryExW(LPCWSTR path, HANDLE file, DWORD flags) {
    HMODULE result = g_load_library_ex_w(path, file, flags);
    DWORD error = GetLastError();
    log_line("LoadLibraryExW path=%p file=%p flags=0x%08lX result=%p gle=%lu", path, file, flags, result, error);
    SetLastError(error);
    return result;
}

extern "C" FARPROC WINAPI observe_GetProcAddress(HMODULE module, LPCSTR name) {
    FARPROC result = g_get_proc_address(module, name);
    DWORD error = GetLastError();
    char ordinal[32];
    log_line("GetProcAddress module=%p name=%s result=%p gle=%lu", module,
             name_or_ordinal(name, ordinal, sizeof(ordinal)), result, error);
    SetLastError(error);
    return result;
}

static bool replace_iat_slot(IMAGE_THUNK_DATA32* slot, void* replacement) {
    DWORD old_protect = 0;
    if (!VirtualProtect(slot, sizeof(slot->u1.Function), PAGE_READWRITE, &old_protect)) return false;
    slot->u1.Function = (DWORD)(ULONG_PTR)replacement;
    DWORD ignored = 0;
    VirtualProtect(slot, sizeof(slot->u1.Function), old_protect, &ignored);
    return true;
}

static void** forward_slot_for(const char* name, void* replacement) {
    if (replacement == (void*)observe_LoadLibraryA) return (void**)&g_load_library_a;
    if (replacement == (void*)observe_LoadLibraryW) return (void**)&g_load_library_w;
    if (replacement == (void*)observe_LoadLibraryExA) return (void**)&g_load_library_ex_a;
    if (replacement == (void*)observe_LoadLibraryExW) return (void**)&g_load_library_ex_w;
    if (replacement == (void*)observe_GetProcAddress) return (void**)&g_get_proc_address;
    log_line("hook_install name=%s result=internal-selector-failure", name);
    return nullptr;
}

static void maybe_install_hook(const char* name, IMAGE_THUNK_DATA32* iat) {
    void* prior = (void*)(ULONG_PTR)iat->u1.Function;
    void* replacement = nullptr;
    if (strcmp(name, "LoadLibraryA") == 0) replacement = (void*)observe_LoadLibraryA;
    else if (strcmp(name, "LoadLibraryW") == 0) replacement = (void*)observe_LoadLibraryW;
    else if (strcmp(name, "LoadLibraryExA") == 0) replacement = (void*)observe_LoadLibraryExA;
    else if (strcmp(name, "LoadLibraryExW") == 0) replacement = (void*)observe_LoadLibraryExW;
    else if (strcmp(name, "GetProcAddress") == 0) replacement = (void*)observe_GetProcAddress;
    else return;
    if (!prior || prior == replacement) {
        log_line("hook_install name=%s result=skipped-invalid-prior", name);
        return;
    }
    void** forward = forward_slot_for(name, replacement);
    if (!forward) return;
    if (!cs_same_or_unset_forward(*forward, prior)) {
        log_line("hook_install name=%s result=skipped-ambiguous-prior first=%p later=%p", name, *forward, prior);
        return;
    }
    if (!*forward) *forward = prior; // publish the real/DxWnd target before IAT replacement.
    if (!replace_iat_slot(iat, replacement)) {
        log_line("hook_install name=%s result=failed gle=%lu", name, GetLastError());
        return;
    }
    log_line("hook_install name=%s prior_target=%p result=installed", name, prior);
    ++g_hooks_installed;
}

static bool terminated_string_in_image(const BYTE* base, DWORD rva, DWORD image_size) {
    return cs_rva_range(rva, 1, image_size) && memchr(base + rva, 0, image_size - rva) != nullptr;
}

static bool write_import_inventory() {
    HMODULE main_module = GetModuleHandleA(nullptr);
    const BYTE* base = (const BYTE*)main_module;
    const IMAGE_DOS_HEADER* dos = (const IMAGE_DOS_HEADER*)base;
    if (!main_module || dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0 ||
        dos->e_lfanew > 0x1000) {
        log_line("observer_error main module is not MZ");
        return false;
    }
    const IMAGE_NT_HEADERS32* nt = (const IMAGE_NT_HEADERS32*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        log_line("observer_error main module is not PE32");
        return false;
    }
    const IMAGE_DATA_DIRECTORY& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    log_line("main_module=%p image_base=0x%08lX size_of_image=0x%08lX import_rva=0x%08lX import_size=0x%08lX",
             main_module, nt->OptionalHeader.ImageBase, nt->OptionalHeader.SizeOfImage, dir.VirtualAddress, dir.Size);
    if (!dir.VirtualAddress || !dir.Size) {
        log_line("inventory status=complete imports=none hooks_installed=%lu", g_hooks_installed);
        return true;
    }
    if (!cs_rva_range(dir.VirtualAddress, dir.Size, nt->OptionalHeader.SizeOfImage)) {
        log_line("observer_error import directory outside SizeOfImage");
        return false;
    }

    const IMAGE_IMPORT_DESCRIPTOR* descriptor =
        (const IMAGE_IMPORT_DESCRIPTOR*)(base + dir.VirtualAddress);
    const DWORD max_descriptors = dir.Size / sizeof(*descriptor);
    bool inventory_valid = max_descriptors != 0;
    if (!inventory_valid) log_line("observer_error import directory is smaller than one descriptor");
    for (DWORD descriptor_index = 0; descriptor_index < max_descriptors && descriptor->Name;
         ++descriptor_index, ++descriptor) {
        if (!terminated_string_in_image(base, descriptor->Name, nt->OptionalHeader.SizeOfImage)) {
            log_line("observer_error import descriptor %lu has invalid DLL name RVA", descriptor_index);
            inventory_valid = false;
            continue;
        }
        const char* dll = (const char*)(base + descriptor->Name);
        if (!descriptor->OriginalFirstThunk) {
            log_line("import dll=%s names=unresolved reason=OriginalFirstThunk-zero", dll);
            continue; // FirstThunk is now live function pointers, not name RVAs.
        }
        if (!cs_rva_range(descriptor->OriginalFirstThunk, sizeof(IMAGE_THUNK_DATA32), nt->OptionalHeader.SizeOfImage) ||
            !cs_rva_range(descriptor->FirstThunk, sizeof(IMAGE_THUNK_DATA32), nt->OptionalHeader.SizeOfImage)) {
            log_line("observer_error import dll=%s thunk RVA outside SizeOfImage", dll);
            inventory_valid = false;
            continue;
        }
        const IMAGE_THUNK_DATA32* names = (const IMAGE_THUNK_DATA32*)(base +
            descriptor->OriginalFirstThunk);
        const IMAGE_THUNK_DATA32* iat = (const IMAGE_THUNK_DATA32*)(base + descriptor->FirstThunk);
        const DWORD max_thunks = (nt->OptionalHeader.SizeOfImage - descriptor->OriginalFirstThunk) / sizeof(*names);
        for (DWORD thunk_index = 0; thunk_index < max_thunks && names->u1.AddressOfData; ++thunk_index, ++names, ++iat) {
            DWORD names_rva = (DWORD)((const BYTE*)names - base);
            DWORD iat_rva = (DWORD)((const BYTE*)iat - base);
            if (!cs_rva_range(names_rva, sizeof(*names), nt->OptionalHeader.SizeOfImage) ||
                !cs_rva_range(iat_rva, sizeof(*iat), nt->OptionalHeader.SizeOfImage)) {
                log_line("observer_error import dll=%s thunk %lu outside SizeOfImage", dll, thunk_index);
                inventory_valid = false;
                break;
            }
            char ordinal[32];
            const char* import_name = nullptr;
            if (IMAGE_SNAP_BY_ORDINAL32(names->u1.Ordinal)) {
                sprintf_s(ordinal, sizeof(ordinal), "#%u", cs_import_ordinal(names->u1.Ordinal));
                import_name = ordinal;
            } else {
                if (!cs_rva_range(names->u1.AddressOfData, sizeof(WORD) + 1, nt->OptionalHeader.SizeOfImage) ||
                    !terminated_string_in_image(base, names->u1.AddressOfData + sizeof(WORD), nt->OptionalHeader.SizeOfImage)) {
                    log_line("observer_error import dll=%s thunk %lu has invalid name RVA", dll, thunk_index);
                    inventory_valid = false;
                    continue;
                }
                const IMAGE_IMPORT_BY_NAME* by_name =
                    (const IMAGE_IMPORT_BY_NAME*)(base + names->u1.AddressOfData);
                import_name = (const char*)by_name->Name;
            }
            log_line("import dll=%s name=%s iat=%p target=%p", dll, import_name,
                     (const void*)iat, (const void*)(ULONG_PTR)iat->u1.Function);
            if (!IMAGE_SNAP_BY_ORDINAL32(names->u1.Ordinal)) maybe_install_hook(import_name, (IMAGE_THUNK_DATA32*)iat);
        }
    }
    log_line("inventory status=%s hooks_installed=%lu", inventory_valid ? "complete" : "invalid",
             g_hooks_installed);
    return inventory_valid;
}

static DWORD WINAPI observer_thread(LPVOID) {
    char path[MAX_PATH] = "";
    DWORD length = GetEnvironmentVariableA("CS_OBSERVER_LOG", path, sizeof(path));
    if (!length || length >= sizeof(path)) return 0;
    g_log = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_NEW,
                        FILE_ATTRIBUTE_NORMAL, nullptr);
    if (g_log == INVALID_HANDLE_VALUE) return 0;
    InitializeCriticalSection(&g_log_lock);
    g_log_lock_ready = true;
    log_line("observer=attached pid=%lu tid=%lu", GetCurrentProcessId(), GetCurrentThreadId());
    log_process_provenance();
    log_passive_display_sample("initial");
    if (!write_import_inventory()) {
        log_line("observer=not-ready pid=%lu reason=invalid-inventory", GetCurrentProcessId());
        return 0;
    }
    log_line("observer=ready pid=%lu inventory=complete hooks_installed=%lu", GetCurrentProcessId(),
             g_hooks_installed);
    Sleep(5000); // one passive later sample; no pacing loop or window control.
    log_passive_display_sample("later_5s");
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(instance);
        HANDLE thread = CreateThread(nullptr, 0, observer_thread, nullptr, 0, nullptr);
        if (thread) CloseHandle(thread);
    } else if (reason == DLL_PROCESS_DETACH && g_log != INVALID_HANDLE_VALUE) {
        CloseHandle(g_log);
        g_log = INVALID_HANDLE_VALUE;
        if (g_log_lock_ready) {
            DeleteCriticalSection(&g_log_lock);
            g_log_lock_ready = false;
        }
    }
    return TRUE;
}
