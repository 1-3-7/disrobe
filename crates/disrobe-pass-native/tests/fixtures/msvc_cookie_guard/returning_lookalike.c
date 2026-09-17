__declspec(noinline) unsigned long long __report_gsfailure(unsigned long long value) {
    return value + 3;
}

unsigned long long returning_cookie_lookalike(unsigned long long value) {
    return __report_gsfailure(value) + 1;
}
