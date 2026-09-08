// Harmless x86 process for proving chain-forward IAT hooks. It loads only the
// supplied observer and provider DLLs, waits for observer readiness, then
// compares direct-IAT LoadLibraryA/GetProcAddress results before and after.
#include <windows.h>
#include <cstdio>
#include <cstring>

typedef int (__cdecl* FixtureFunction)();

struct CallOutcome {
    HMODULE module;
    FARPROC named;
    FARPROC ordinal;
    DWORD load_error;
    DWORD named_error;
    DWORD ordinal_error;
    int named_value;
    int ordinal_value;
};

static CallOutcome call_live_iat(const char* provider_path) {
    CallOutcome outcome = {};
    SetLastError(0x2A01);
    outcome.module = LoadLibraryA(provider_path);
    outcome.load_error = GetLastError();
    if (!outcome.module) return outcome;

    SetLastError(0x2A02);
    outcome.named = GetProcAddress(outcome.module, "cs_fixture_named");
    outcome.named_error = GetLastError();
    if (outcome.named) outcome.named_value = ((FixtureFunction)outcome.named)();

    SetLastError(0x2A03);
    outcome.ordinal = GetProcAddress(outcome.module, MAKEINTRESOURCEA(7));
    outcome.ordinal_error = GetLastError();
    if (outcome.ordinal) outcome.ordinal_value = ((FixtureFunction)outcome.ordinal)();
    return outcome;
}

static bool same_outcome(const CallOutcome& before, const CallOutcome& after) {
    return before.module == after.module &&
           before.named == after.named &&
           before.ordinal == after.ordinal &&
           before.load_error == after.load_error &&
           before.named_error == after.named_error &&
           before.ordinal_error == after.ordinal_error &&
           before.named_value == after.named_value &&
           before.ordinal_value == after.ordinal_value;
}

static bool observer_ready(const char* log_path) {
    HANDLE file = CreateFileA(log_path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    char text[65536] = {};
    DWORD length = 0;
    const bool read_ok = ReadFile(file, text, sizeof(text) - 1, &length, nullptr) != FALSE;
    CloseHandle(file);
    char marker[96];
    sprintf_s(marker, "observer=ready pid=%lu inventory=complete hooks_installed=", GetCurrentProcessId());
    return read_ok && strstr(text, marker) != nullptr;
}

static void print_outcome(FILE* output, const char* label, const CallOutcome& value) {
    fprintf(output,
            "%s module=%p load_error=%lu named=%p named_error=%lu named_value=%d "
            "ordinal=%p ordinal_error=%lu ordinal_value=%d\n",
            label, value.module, value.load_error, value.named, value.named_error,
            value.named_value, value.ordinal, value.ordinal_error, value.ordinal_value);
}

int main(int argc, char** argv) {
    if (argc != 4) {
        fprintf(stderr, "usage: cs_observer_forwarding_fixture OBSERVER.dll PROVIDER.dll RESULT.txt\n");
        return 2;
    }
    const char* observer_path = argv[1];
    const char* provider_path = argv[2];
    const char* result_path = argv[3];
    char log_path[MAX_PATH] = {};
    const DWORD log_length = GetEnvironmentVariableA("CS_OBSERVER_LOG", log_path, sizeof(log_path));
    if (!log_length || log_length >= sizeof(log_path)) {
        fprintf(stderr, "CS_OBSERVER_LOG is required\n");
        return 2;
    }

    // Preload makes both measured LoadLibraryA calls observe the same loaded state.
    if (!LoadLibraryA(provider_path)) {
        fprintf(stderr, "provider preload failed gle=%lu\n", GetLastError());
        return 1;
    }
    const CallOutcome before = call_live_iat(provider_path);
    const HMODULE observer = LoadLibraryA(observer_path);
    if (!observer) {
        fprintf(stderr, "observer load failed gle=%lu\n", GetLastError());
        return 1;
    }

    const ULONGLONG deadline = GetTickCount64() + 6000;
    while (!observer_ready(log_path) && GetTickCount64() < deadline) Sleep(10);
    const bool ready = observer_ready(log_path);
    const CallOutcome after = ready ? call_live_iat(provider_path) : CallOutcome{};
    const bool values_valid = before.module && before.named && before.ordinal &&
                              before.named_value == 0x1357 && before.ordinal_value == 0x2468 &&
                              after.module && after.named && after.ordinal &&
                              after.named_value == 0x1357 && after.ordinal_value == 0x2468;
    const bool equivalent = ready && values_valid && same_outcome(before, after);

    FILE* result = nullptr;
    fopen_s(&result, result_path, "wx");
    if (!result) {
        fprintf(stderr, "result path must be fresh\n");
        return 2;
    }
    fprintf(result, "observer_ready=%s\n", ready ? "true" : "false");
    print_outcome(result, "before", before);
    print_outcome(result, "after", after);
    fprintf(result, "forwarding_equivalent=%s\n", equivalent ? "true" : "false");
    fclose(result);
    return equivalent ? 0 : 1;
}
