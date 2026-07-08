@interface NSString
+ (id)stringWithUTF8String:(const char *)s;
- (unsigned long)length;
@end

@interface NSArray
- (id)objectAtIndex:(unsigned long)i;
@end

@interface NSObject
+ (id)alloc;
- (id)init;
- (void)setValue:(id)v forKey:(id)k;
@end

id make_greeting(const char *raw) {
    return [NSString stringWithUTF8String:raw];
}

id first_element(NSArray *arr) {
    return [arr objectAtIndex:0];
}

void store(NSObject *obj, id v, id k) {
    [obj setValue:v forKey:k];
}

unsigned long text_length(NSString *s) {
    return [s length];
}

id fresh_object(void) {
    return [[NSObject alloc] init];
}
