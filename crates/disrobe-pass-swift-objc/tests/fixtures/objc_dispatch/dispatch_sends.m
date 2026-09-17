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

struct DispatchRecord {
    unsigned long first;
    unsigned long second;
    unsigned long third;
};

@interface Courier : NSObject
- (id)describe;
- (struct DispatchRecord)superSummaryFirst:(unsigned long)first second:(unsigned long)second third:(unsigned long)third fourth:(unsigned long)fourth;
@end

@interface FastCourier : Courier
- (id)describe;
- (struct DispatchRecord)superSummaryFirst:(unsigned long)first second:(unsigned long)second third:(unsigned long)third fourth:(unsigned long)fourth;
@end

@interface Parcel : NSObject
+ (struct DispatchRecord)classSummaryFirst:(unsigned long)first second:(unsigned long)second third:(unsigned long)third fourth:(unsigned long)fourth;
- (struct DispatchRecord)instanceSummaryFirst:(unsigned long)first second:(unsigned long)second third:(unsigned long)third fourth:(unsigned long)fourth;
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

struct DispatchRecord class_summary(unsigned long first, unsigned long second, unsigned long third, unsigned long fourth) {
    return [Parcel classSummaryFirst:first second:second third:third fourth:fourth];
}

struct DispatchRecord dynamic_summary(Parcel *parcel, unsigned long first, unsigned long second, unsigned long third, unsigned long fourth) {
    return [parcel instanceSummaryFirst:first second:second third:third fourth:fourth];
}

@implementation FastCourier
- (id)describe {
    return [super describe];
}

- (struct DispatchRecord)superSummaryFirst:(unsigned long)first second:(unsigned long)second third:(unsigned long)third fourth:(unsigned long)fourth {
    return [super superSummaryFirst:first second:second third:third fourth:fourth];
}
@end
