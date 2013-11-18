//
//  CryptoDigest.h
//  HDC-Pilot
//
//  Created by Jon Lochner on 5/11/11.
//

#import <Foundation/Foundation.h>
#import "NSString+Digest.h"
#import "NSData+Digest.h"

@interface CryptoDigest : NSObject {
    
}

+(NSString*)sha1Digest:(NSString*)input;
+(NSString*)sha256Digest:(NSString*)input;
+(NSString*)sha512Digest:(NSString*)input;

@end
