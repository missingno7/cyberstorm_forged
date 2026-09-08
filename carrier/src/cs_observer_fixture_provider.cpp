// Harmless x86 export provider for cs_observer_forwarding_fixture.exe.
extern "C" __declspec(dllexport) int cs_fixture_named() {
    return 0x1357;
}

extern "C" __declspec(dllexport) int cs_fixture_ordinal() {
    return 0x2468;
}
