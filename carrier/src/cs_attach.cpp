// Explicit-PID x86 attach helper. The controller owns the DxWnd/game job;
// this program only verifies one already-owned CSTORM process and injects once.
#include <windows.h>
#include <tlhelp32.h>
#include <cstdio>
#include <cstdarg>
#include <cstdlib>
#include <cstring>

static bool full_path(const char* input, char output[MAX_PATH]) {
    const DWORD length = GetFullPathNameA(input, MAX_PATH, output, nullptr);
    return length != 0 && length < MAX_PATH;
}

static bool same_path(const char* left, const char* right) {
    char left_full[MAX_PATH] = {}, right_full[MAX_PATH] = {};
    return full_path(left, left_full) && full_path(right, right_full) &&
           _stricmp(left_full, right_full) == 0;
}

static void note(FILE* file, const char* format, ...) {
    va_list arguments;
    va_start(arguments, format);
    vfprintf(file, format, arguments);
    va_end(arguments);
    fputc('\n', file);
}

static bool is_pe32_i386_file(const char* path) {
    FILE* file = nullptr;
    if (fopen_s(&file, path, "rb") != 0 || !file) return false;
    IMAGE_DOS_HEADER dos = {};
    const bool dos_ok = fread(&dos, sizeof(dos), 1, file) == 1 &&
                        dos.e_magic == IMAGE_DOS_SIGNATURE && dos.e_lfanew >= 0 &&
                        fseek(file, dos.e_lfanew, SEEK_SET) == 0;
    IMAGE_NT_HEADERS32 nt = {};
    const bool nt_ok = dos_ok && fread(&nt, sizeof(nt), 1, file) == 1 &&
                       nt.Signature == IMAGE_NT_SIGNATURE && nt.FileHeader.Machine == IMAGE_FILE_MACHINE_I386 &&
                       nt.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC;
    fclose(file);
    return nt_ok;
}

static bool find_module_path(DWORD process_id, const char* expected_path,
                             MODULEENTRY32* result, FILE* report) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, process_id);
    if (snapshot == INVALID_HANDLE_VALUE) return false;
    MODULEENTRY32 entry = {};
    entry.dwSize = sizeof(entry);
    bool found = false;
    if (Module32First(snapshot, &entry)) {
        do {
            if (same_path(entry.szExePath, expected_path)) {
                *result = entry;
                note(report, "module path=%s base=%p size=0x%08lX", entry.szExePath,
                     entry.modBaseAddr, entry.modBaseSize);
                found = true;
                break;
            }
        } while (Module32Next(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return found;
}

static bool module_basename_present(DWORD process_id, const char* expected_name, FILE* report) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, process_id);
    if (snapshot == INVALID_HANDLE_VALUE) return false;
    MODULEENTRY32 entry = {};
    entry.dwSize = sizeof(entry);
    bool found = false;
    if (Module32First(snapshot, &entry)) {
        do {
            if (_stricmp(entry.szModule, expected_name) == 0) {
                note(report, "required_module path=%s base=%p size=0x%08lX", entry.szExePath,
                     entry.modBaseAddr, entry.modBaseSize);
                found = true;
                break;
            }
        } while (Module32Next(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return found;
}

static bool remote_load_library_address(DWORD process_id, LPTHREAD_START_ROUTINE* remote_load,
                                        FILE* report) {
    FARPROC local_load = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryW");
    HMODULE local_owner = nullptr;
    if (!local_load || !GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                           GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                           (LPCSTR)local_load, &local_owner)) {
        return false;
    }
    char owner_path[MAX_PATH] = {};
    if (!GetModuleFileNameA(local_owner, owner_path, sizeof(owner_path))) return false;
    MODULEENTRY32 remote_owner = {};
    if (!find_module_path(process_id, owner_path, &remote_owner, report)) return false;
    const ULONG_PTR offset = (ULONG_PTR)local_load - (ULONG_PTR)local_owner;
    *remote_load = (LPTHREAD_START_ROUTINE)((BYTE*)remote_owner.modBaseAddr + offset);
    note(report, "remote_loadlibraryw owner=%s rva=0x%08lX address=%p", owner_path,
         (unsigned long)offset, *remote_load);
    return true;
}

int main(int argc, char** argv) {
    if (argc != 9 || strcmp(argv[1], "--attach") || strcmp(argv[3], "--dll") ||
        strcmp(argv[5], "--expected-image") || strcmp(argv[7], "--report")) {
        fprintf(stderr, "usage: cs_attach --attach PID --dll OBSERVER.dll --expected-image CSTORM.EXE --report OUT.txt\n");
        return 2;
    }
    char* end = nullptr;
    const unsigned long raw_pid = strtoul(argv[2], &end, 10);
    if (!raw_pid || !end || *end) {
        fprintf(stderr, "invalid PID\n");
        return 2;
    }
    FILE* report = nullptr;
    fopen_s(&report, argv[8], "wx");
    if (!report) {
        fprintf(stderr, "report must be fresh\n");
        return 2;
    }

    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
                                 PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, (DWORD)raw_pid);
    if (!process) {
        note(report, "error=OpenProcess gle=%lu", GetLastError());
        fclose(report);
        return 1;
    }
    char image[MAX_PATH] = {};
    DWORD image_size = sizeof(image);
    BOOL helper_wow64 = FALSE, target_wow64 = FALSE;
    MODULEENTRY32 target_image = {};
    if (!QueryFullProcessImageNameA(process, 0, image, &image_size) || !same_path(image, argv[6]) ||
        !IsWow64Process(GetCurrentProcess(), &helper_wow64) || !IsWow64Process(process, &target_wow64) ||
        helper_wow64 != target_wow64 || !is_pe32_i386_file(argv[6]) ||
        !find_module_path((DWORD)raw_pid, argv[6], &target_image, report) ||
        !module_basename_present((DWORD)raw_pid, "dxwnd.dll", report)) {
        note(report, "error=target-verification image=%s helper_wow64=%d target_wow64=%d gle=%lu", image,
             helper_wow64, target_wow64, GetLastError());
        CloseHandle(process);
        fclose(report);
        return 1;
    }
    note(report, "target_architecture=x86 target_image_base=%p", target_image.modBaseAddr);

    char dll[MAX_PATH] = {};
    if (!full_path(argv[4], dll) || GetFileAttributesA(dll) == INVALID_FILE_ATTRIBUTES) {
        note(report, "error=observer-not-found");
        CloseHandle(process);
        fclose(report);
        return 1;
    }
    LPTHREAD_START_ROUTINE remote_load = nullptr;
    if (!remote_load_library_address((DWORD)raw_pid, &remote_load, report)) {
        note(report, "error=remote-loadlibrary-address gle=%lu", GetLastError());
        CloseHandle(process);
        fclose(report);
        return 1;
    }

    wchar_t wide[MAX_PATH] = {};
    if (!MultiByteToWideChar(CP_ACP, 0, dll, -1, wide, MAX_PATH)) {
        note(report, "error=observer-path-conversion gle=%lu", GetLastError());
        CloseHandle(process);
        fclose(report);
        return 1;
    }
    const SIZE_T bytes = (wcslen(wide) + 1) * sizeof(wchar_t);
    SIZE_T written = 0;
    void* remote_path = VirtualAllocEx(process, nullptr, bytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!remote_path || !WriteProcessMemory(process, remote_path, wide, bytes, &written) || written != bytes) {
        note(report, "error=remote-path-write gle=%lu", GetLastError());
        if (remote_path) VirtualFreeEx(process, remote_path, 0, MEM_RELEASE);
        CloseHandle(process);
        fclose(report);
        return 1;
    }
    HANDLE thread = CreateRemoteThread(process, nullptr, 0, remote_load, remote_path, 0, nullptr);
    if (!thread) {
        note(report, "error=remote-load-create gle=%lu", GetLastError());
        VirtualFreeEx(process, remote_path, 0, MEM_RELEASE);
        CloseHandle(process);
        fclose(report);
        return 1;
    }
    const DWORD wait = WaitForSingleObject(thread, 10000);
    if (wait != WAIT_OBJECT_0) {
        note(report, "error=remote-load-incomplete wait=0x%08lX remote_path_retained_until_controller_job_cleanup=true",
             wait);
        CloseHandle(thread);
        CloseHandle(process);
        fclose(report);
        return 1;
    }
    DWORD result = 0;
    GetExitCodeThread(thread, &result);
    CloseHandle(thread);
    VirtualFreeEx(process, remote_path, 0, MEM_RELEASE);
    const bool loaded = result != 0 && find_module_path((DWORD)raw_pid, dll, &target_image, report);
    note(report, "remote_loadlibraryw_module=0x%08lX observer_loaded=%s", result, loaded ? "true" : "false");
    CloseHandle(process);
    fclose(report);
    return loaded ? 0 : 1;
}
