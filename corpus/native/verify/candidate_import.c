extern unsigned int imported_target(unsigned int value);

unsigned int verify_import(unsigned int value) {
    return imported_target(value);
}
