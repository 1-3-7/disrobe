static unsigned char blob[10] = { 0x23, 0x2e, 0x27, 0x27, 0x24, 0x3c, 0x24, 0x39, 0x27, 0x2f };

__attribute__((export_name("plaintext_ptr")))
unsigned char *plaintext_ptr(void) {
  for (int i = 0; i < 10; i++) {
    unsigned char c = blob[i];
    blob[i] = (unsigned char)(c ^ 0x4b);
  }
  return blob;
}
