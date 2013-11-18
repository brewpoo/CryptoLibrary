//
//  NSString+Extract.m
//  OBTIM
//
//  Created by Jon Lochner on 4/1/13.
//

#import "NSString+Extract.h"

@implementation NSString (Extract)

- (NSString*)stringBetweenString:(NSString*)startToken andString:(NSString*)endToken {
    NSScanner* scanner = [NSScanner scannerWithString:self];
    [scanner setCharactersToBeSkipped:nil];
    [scanner scanUpToString:startToken intoString:NULL];
    if ([scanner scanString:startToken  intoString:NULL]) {
        NSString* result = nil;
        if ([scanner scanUpToString:endToken intoString:&result]) {
            return result;
        }
    }
    return nil;
}

@end
