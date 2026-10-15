#define EXPORT __attribute__((visibility("default"), used))

#define HEADER(length) \
    "\xf5\xf5\xdc\xdc" length "\x03\x00\x00\x00\x00\x00\x00\x00" \
    "ace654289f5abc240509fc941453ebc5" \
    "product no-code_comments no-dwarf_stack_traces_mode dedup_instructions " \
    "no-asan no-msan no-tsan no-shared_data " FEATURES

EXPORT const unsigned char _kDartVmSnapshotData[] =
    HEADER("\x90\x00\x00\x00\x00\x00\x00\x00");
EXPORT const unsigned char _kDartIsolateSnapshotData[] =
    HEADER("\x90\x00\x00\x00\x00\x00\x00\x00");
EXPORT const unsigned char _kDartVmSnapshotInstructions[16] = {0};
EXPORT const unsigned char _kDartIsolateSnapshotInstructions[16] = {0};
