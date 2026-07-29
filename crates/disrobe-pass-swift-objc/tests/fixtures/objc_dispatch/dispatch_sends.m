@interface NSString
+ (id)stringWithUTF8String:(const char *)s;
+ (id)string;
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

@interface Courier : NSObject
- (id)describe;
@end

@interface FastCourier : Courier
- (id)describe;
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

id clobbered_receiver(NSArray *arr, const char *raw) {
    id produced = [NSString stringWithUTF8String:raw];
    return [(NSArray *)produced objectAtIndex:0];
}

unsigned long chained_receiver(NSArray *arr) {
    return [[arr objectAtIndex:0] length];
}

id instance_then_class(NSArray *arr, const char *raw) {
    [arr objectAtIndex:0];
    return [NSString stringWithUTF8String:raw];
}

id branch_shared_classref(int flag, const char *raw) {
    if (flag) {
        return [NSString stringWithUTF8String:raw];
    }
    return [NSString string];
}

@implementation FastCourier
- (id)describe {
    return [super describe];
}
@end
