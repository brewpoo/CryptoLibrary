//
//  NSString+Extract.h
//  OBTIM
//
//  Created by Jon Lochner on 4/1/13.
//

#import <Foundation/Foundation.h>

@interface NSString (Extract)

- (NSString*)stringBetweenString:(NSString*)startToken andString:(NSString*)endToken;

@end
