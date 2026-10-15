const volatile char kFuseWire[] =
    "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX"
    "\x01\x09"
    "101100011";

int start(void) {
    return kFuseWire[34];
}
