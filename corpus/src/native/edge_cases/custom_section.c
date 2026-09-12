__attribute__((section(".disrobe_marker"))) const char marker[] = "DISROBE-CUSTOM-SECTION-V1";

int main(void) {
    return (int)(marker[0] - marker[0]);
}
