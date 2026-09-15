#pragma strict_gs_check(on)

__declspec(noinline) unsigned long long cookie_guard(unsigned long long value) {
    unsigned char buffer[32];
    *buffer = (unsigned char)value;
    return *buffer + 1;
}
