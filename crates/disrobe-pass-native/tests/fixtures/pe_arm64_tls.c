typedef void (*TlsCallback)(void *, unsigned long, void *);

typedef struct {
    void *raw_data_start;
    void *raw_data_end;
    unsigned long *index;
    TlsCallback *callbacks;
    unsigned long zero_fill;
    unsigned long characteristics;
} TlsDirectory;

#pragma section(".tls$AAA", read, write)
#pragma section(".tls$ZZZ", read, write)
#pragma section(".CRT$XLB", read)
#pragma section(".CRT$XLZ", read)
#pragma section(".rdata$T", read)

__declspec(allocate(".tls$AAA")) unsigned char tls_raw_start;
__declspec(allocate(".tls$ZZZ")) unsigned char tls_raw_end;
unsigned long tls_index;
volatile unsigned long tls_observed;

__declspec(noinline) void tls_probe(void *module, unsigned long reason, void *reserved) {
    tls_observed = reason + (module != reserved);
}

__declspec(allocate(".CRT$XLB")) TlsCallback tls_callbacks[] = {tls_probe};
__declspec(allocate(".CRT$XLZ")) TlsCallback tls_callbacks_end[] = {0};

__declspec(allocate(".rdata$T")) const TlsDirectory _tls_used = {
    &tls_raw_start,
    &tls_raw_end,
    &tls_index,
    tls_callbacks,
    0,
    0,
};

int main_probe(void) {
    return 17;
}
