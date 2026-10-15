@interface Probe
- (int)frobnicate;
@end

extern id make_object(void);
extern void consume_object(id object);
extern void consume_bytes(volatile char *bytes, int count);

int main(void) {
    volatile char buf[48];
    for (int i = 0; i < 40; i++) {
        buf[i] = (char)i;
    }
    consume_bytes(buf, 40);
    id value = make_object();
    int result = [value frobnicate];
    consume_object(value);
    return result + buf[3];
}
