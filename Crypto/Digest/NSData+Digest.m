//
//  NSData+Digest.m
//  OBTIM
//
//  Created by Jon Lochner on 4/2/13.
//

#import "NSData+Digest.h"
#import <CommonCrypto/CommonDigest.h>

@implementation NSData (Digest)

-(NSData*)sha1Digest {
    unsigned char digest[CC_SHA1_DIGEST_LENGTH];
    CC_SHA1(self.bytes, self.length, digest);
    return [NSData dataWithBytes:&digest length:CC_SHA1_DIGEST_LENGTH];
}

-(NSData*)sha256Digest {
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(self.bytes, self.length, digest);
    return [NSData dataWithBytes:&digest length:CC_SHA256_DIGEST_LENGTH];
}

-(NSData*)sha512Digest {
    unsigned char digest[CC_SHA512_DIGEST_LENGTH];
    CC_SHA512(self.bytes, self.length, digest);
    return [NSData dataWithBytes:&digest length:CC_SHA512_DIGEST_LENGTH];
}

-(NSString*)hex {
    NSMutableString* output = [NSMutableString stringWithCapacity:self.length * 2];
    const unsigned char* bytes = (const unsigned char*)[self bytes];
    for(int i = 0; i < self.length; i++)
        [output appendFormat:@"%02x", bytes[i]];
    return output;
}

@end
