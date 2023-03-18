#import "KittyScanner.h"
#import "KittyUtils.h"
#include <os/log.h>

@implementation KittyScanner

+ (BOOL)compare:(const char *)data pattern:(const char *)pattern mask:(const char *)mask {
    for (; *mask; ++mask, ++data, ++pattern) {
        if (*mask == 'x' && *data != *pattern) {
            return NO;
        }
    }
    return !*mask;
}

+ (uintptr_t)findInRange:(uintptr_t)start end:(size_t)end pattern:(const char *)pattern mask:(const char *)mask {
    const size_t scan_size = strlen(mask);

    if ((start + scan_size) > end) {
        return 0;
    }

    const size_t length = end - start;

    for (size_t i = 0; i < length; ++i) {
        const uintptr_t current_end = start + i + scan_size;
        if (current_end > end) {
            break;
        }

        if (![KittyScanner compare:(const char *)(start + i) pattern:pattern mask:mask]) {
            continue;
        }

        return start + i;
    }
    return 0;
}

+ (NSArray<NSNumber *> *)findBytesAll:(const struct mach_header *)header segment:(const char *)segment bytes:(const char *)bytes mask:(const char *)mask {
    NSMutableArray<NSNumber *> *list = [NSMutableArray array];
    if (!header || !segment || !bytes || !mask) {
        return list;
    }

#if defined(__arm64e__) || defined(__arm64__) || defined(__aarch64__)
    const struct mach_header_64 *header_ = (const struct mach_header_64 *)header;
#else
    const struct mach_header *header_ = header;
#endif

    unsigned long seg_size = 0;
    uint8_t *start = getsegmentdata(header_, segment, &seg_size);

    if (!start || seg_size == 0) {
        return list;
    }

    uintptr_t curr_search_address = (uintptr_t)start;
    const size_t scan_size = strlen(mask);
    do {
        if (list.count != 0) {
            curr_search_address = [list.lastObject unsignedLongValue] + scan_size;
        }

        uintptr_t found = [KittyScanner findInRange:curr_search_address end:((uintptr_t)start + seg_size) pattern:bytes mask:mask];
        if (!found) {
            break;
        }

        [list addObject:@(found)];
    } while (true);

    return list;
}

+ (uintptr_t)findBytesFirst:(const struct mach_header *)header segment:(const char *)segment bytes:(const char *)bytes mask:(const char *)mask {
    if (!header || !segment || !bytes || !mask) {
        return 0;
    }

#if defined(__arm64e__) || defined(__arm64__) || defined(__aarch64__)
    const struct mach_header_64 *header_ = (const struct mach_header_64 *)header;
#else
    const struct mach_header *header_ = header;
#endif

    unsigned long seg_size = 0;
    uint8_t *start = getsegmentdata(header_, segment, &seg_size);
    if (!start || seg_size == 0) {
        return 0;
    }
    
    return [KittyScanner findInRange:(uintptr_t)start end:((uintptr_t)start + seg_size) pattern:bytes mask:mask];
}

+ (NSArray<NSNumber *> *)findHexAll:(const struct mach_header *)header segment:(const char *)segment hex:(NSString *)hex mask:(const char *)mask {
    NSMutableArray<NSNumber *> *list = [NSMutableArray array];
    
    if (!header || !segment || !mask || ![KittyUtils validateHexString:&hex]) {
        return list;
    }

    const size_t scan_size = strlen(mask);
    
    if ((hex.length / 2) != scan_size) {
        return list;
    }

    NSMutableData *bytes = [NSMutableData dataWithLength:scan_size];
    [KittyUtils fromHex:hex data:[bytes mutableBytes]];
    
    list = [KittyScanner findBytesAll:header segment:segment bytes:(const char *)[bytes mutableBytes] mask:mask].mutableCopy;
    
    return list;
}

+ (uintptr_t)findHexFirst:(const struct mach_header *)header segment:(const char *)segment hex:(NSString *)hex mask:(const char *)mask {
    if (!header || !segment || !mask || ![KittyUtils validateHexString:&hex]) {
        return 0;
    }

    const size_t scan_size = strlen(mask);
    if ((hex.length / 2) != scan_size) {
        return 0;
    }

    NSMutableData *bytes = [NSMutableData dataWithLength:scan_size];
    [KittyUtils fromHex:hex data:[bytes mutableBytes]];
    return [KittyScanner findBytesFirst:header segment:segment bytes:(const char *)[bytes mutableBytes] mask:mask];
}

+ (NSArray<NSNumber *> *)findDataAll:(const struct mach_header *)header segment:(const char *)segment data:(const void *)data size:(size_t)size {
    NSMutableArray<NSNumber *> *list = [NSMutableArray array];

    if (!header || !segment || !data || size < 1) {
        return list;
    }

    NSString *mask = [@"" stringByPaddingToLength:size withString:@"x" startingAtIndex:0];
    list = [KittyScanner findBytesAll:header segment:segment bytes:(const char *)data mask:[mask UTF8String]].mutableCopy;
    return list;
}

+ (uintptr_t)findDataFirst:(const struct mach_header *)header segment:(const char *)segment data:(const void *)data size:(size_t)size {
    if (!header || !segment || !data || size < 1) {
        return 0;
    }

    NSString *mask = [@"" stringByPaddingToLength:size withString:@"x" startingAtIndex:0];
    return [KittyScanner findBytesFirst:header segment:segment bytes:(const char *)data mask:[mask UTF8String]];
}

@end

