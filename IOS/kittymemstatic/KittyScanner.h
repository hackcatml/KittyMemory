#include <Foundation/Foundation.h>
#include <mach-o/dyld.h>
#include <mach-o/getsect.h>
#include <mach/mach.h>

@interface KittyScanner : NSObject

+ (BOOL)compare:(const char *)data pattern:(const char *)pattern mask:(const char *)mask;
+ (uintptr_t)findInRange:(uintptr_t)start end:(uintptr_t)end pattern:(const char *)pattern mask:(const char *)mask;
+ (NSArray<NSNumber *> *)findBytesAll:(const struct mach_header *)header segment:(const char *)segment bytes:(const char *)bytes mask:(const char *)mask;
+ (uintptr_t)findBytesFirst:(const struct mach_header *)header segment:(const char *)segment bytes:(const char *)bytes mask:(const char *)mask;
+ (NSArray<NSNumber *> *)findHexAll:(const struct mach_header *)header segment:(const char *)segment hex:(NSString *)hex mask:(const char *)mask;
+ (uintptr_t)findHexFirst:(const struct mach_header *)header segment:(const char *)segment hex:(NSString *)hex mask:(const char *)mask;
+ (NSArray<NSNumber *> *)findDataAll:(const struct mach_header *)header segment:(const char *)segment data:(const void *)data size:(size_t)size;
+ (uintptr_t)findDataFirst:(const struct mach_header *)header segment:(const char *)segment data:(const void *)data size:(size_t)size;

@end
