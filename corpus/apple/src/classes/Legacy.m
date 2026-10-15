#import <UIKit/UIKit.h>

@protocol FXRefreshing <NSObject>
- (void)refresh:(NSInteger)count;
@end

@interface FXLegacyView : UIView <FXRefreshing>
@property (nonatomic, copy) NSString *title;
@property (nonatomic, readonly) NSInteger ticks;
+ (instancetype)sharedView;
- (void)refresh:(NSInteger)count;
@end

@implementation FXLegacyView {
    NSInteger _ticks;
    double _scale;
}

+ (instancetype)sharedView {
    return [[self alloc] initWithFrame:CGRectZero];
}

- (void)refresh:(NSInteger)count {
    _ticks += count;
    _scale = (double)_ticks / 2.0;
}

- (NSInteger)ticks {
    return _ticks;
}

@end

@interface FXLegacyView (Debug)
- (NSString *)debugSummary;
@end

@implementation FXLegacyView (Debug)
- (NSString *)debugSummary {
    return [NSString stringWithFormat:@"%@ %ld", self.title, (long)_ticks];
}
@end

int fx_add(int a, int b) {
    return a + b;
}

static int fx_hidden(int a) {
    return a * 3;
}

int fx_public_twice(int a) {
    return fx_hidden(a) - a;
}
