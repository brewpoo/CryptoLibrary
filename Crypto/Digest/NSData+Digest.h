//
//  NSData+Digest.h
//  OBTIM
//
//  Created by Jon Lochner on 4/2/13.
//

#import <Foundation/Foundation.h>

@interface NSData (Digest)

-(NSData*)sha1Digest;
-(NSData*)sha256Digest;
-(NSData*)sha512Digest;

-(NSString*)hex;

@end
