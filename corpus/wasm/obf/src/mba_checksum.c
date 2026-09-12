unsigned int mix(unsigned int a, unsigned int b) {
  unsigned int t = (a ^ b) + 2u * (a & b);
  return ((t * 5u) ^ a) * 1103515245u + 12345u;
}

unsigned int blend(unsigned int a, unsigned int b, unsigned int c) {
  unsigned int x = (a ^ b) + 2u * (a & b);
  unsigned int y = (x ^ c) + 2u * (x & c);
  return y * 2654435761u;
}

unsigned int checksum(unsigned int seed, unsigned int count) {
  unsigned int acc = seed;
  for (unsigned int i = 0; i < count; i++) {
    unsigned int k = i + 3u;
    unsigned int step = (acc ^ k) + 2u * (acc & k);
    acc = step * i;
  }
  return acc;
}
