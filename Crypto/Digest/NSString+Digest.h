//
//  NSString+Digest.h
//  OBTIM
//
//  Created by Jon Lochner on 4/2/13.
//

#import <Foundation/Foundation.h>

@interface NSString (Digest)

-(NSData*)sha1Digest;
-(NSData*)sha256Digest;
-(NSData*)sha512Digest;

@end
