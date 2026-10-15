#define EXPORT __attribute__((visibility("default"), used))

EXPORT const char flutter_engine_leading[] = "flutter engine";
EXPORT const char flutter_engine_dart_version[] =
    "3.12.2 (stable) (Tue Jun 9 01:11:39 2026 -0700) on \"" TARGET "\"";
EXPORT const char flutter_engine_snapshot_hash[] = SNAPSHOT_HASH;
EXPORT const char flutter_engine_revision[] = "83675ed27633283e7fc296c8bca22e841224c096";
EXPORT const char flutter_engine_other_revision[] = "e9ed4fc9f1544c58d8a9347c1fc9471d8dd7c465";
EXPORT const char flutter_engine_trailing[] = "engine strings end";
