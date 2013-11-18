//
//  NSString+Digest.m
//  OBTIM
//
//  Created by Jon Lochner on 4/2/13.
//

#import "NSString+Digest.h"
#import <CommonCrypto/CommonDigest.h>

@implementation NSString (Digest)

-(NSData*)sha1Digest {
    const char *cstr = [self cStringUsingEncoding:NSASCIIStringEncoding];
    NSData *data = [NSData dataWithBytes:cstr length:self.length];
    unsigned char digest[CC_SHA1_DIGEST_LENGTH];
    CC_SHA1(data.bytes, data.length, digest);
    return [NSData dataWithBytes:&digest length:CC_SHA1_DIGEST_LENGTH];
   }

-(NSData*) sha256Digest {
    const char *cstr = [self cStringUsingEncoding:NSUTF8StringEncoding];
    NSData *data = [NSData dataWithBytes:cstr length:self.length];
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, data.length, digest);
    return [NSData dataWithBytes:&digest length:CC_SHA256_DIGEST_LENGTH];
   }

-(NSData*) sha512Digest {
    const char *cstr = [self cStringUsingEncoding:NSUTF8StringEncoding];
    NSData *data = [NSData dataWithBytes:cstr length:self.length];
    unsigned char digest[CC_SHA512_DIGEST_LENGTH];
    CC_SHA512(data.bytes, data.length, digest);
    return [NSData dataWithBytes:&digest length:CC_SHA512_DIGEST_LENGTH];
}

@end
