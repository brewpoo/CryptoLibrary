//
//  SecKeyWrapper.h
//  OBTIM
//
//  Created by Jon Lochner on 4/1/13.
//

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonCrypto.h>
#import "Base64.h"
#import "BasicEncodingRules.h"

@interface SecKeyWrapper : NSObject

+ (NSData*)stripPublicKeyHeader:(NSData *)d_key;
+ (NSData*)exportPublicKey:(SecKeyRef)key;

+ (BOOL)removeKeyNamed:(NSString*)name;
+ (SecKeyRef)addPublicKey:(NSData*)keyBits withName:(NSString*)name;
+ (SecKeyRef)addPrivateKey:(NSData*)keyBits withName:(NSString*)name;
+ (SecKeyRef)addSymmetricKey:(NSData*)key withName:(NSString*)name;
+ (SecCertificateRef)addCertificate:(NSData*)certificate withName:(NSString*)name;
+ (SecIdentityRef)addIdentity:(NSData*)identity withName:(NSString*)name andPassword:(NSString*)password;

+ (SecKeyRef)getKeyRefFor:(NSString*)keyName;
+ (SecCertificateRef)getCertRefFor:(NSString*)certName;
+ (SecIdentityRef)getIdentifyRefFor:(NSString*)identityName;

+ (void)enumerateKeychain;
+ (void)describeKeyRef:(SecKeyRef)keyRef;
+ (void)removeAll;
+ (void)removeAll:(CFTypeRef)keyRefClass;

+ (BOOL)generateKeypairNamed:(NSString*)name;
+ (BOOL)generateSymmetricKeyNamed:(NSString*)name;

+ (NSData*)signData:(NSData*)rawData usingKey:(SecKeyRef)key;
+ (BOOL)verifySignature:(NSData*)signedHash ofData:(NSData*)data usingKey:(SecKeyRef)key;

+ (NSData*)encryptData:(NSData*)rawData withKey:(SecKeyRef)key; // Asymmetric
+ (NSData*)decryptData:(NSData*)cipherData withKey:(SecKeyRef)key; // Asymmetric

+ (NSData*)cipherData:(NSData*)dataIn usingKey:(NSData*)key andIv:(NSData*)iv withOperation:(CCOperation)encryptOrDecrypt;
+ (NSData*)encipherData:(NSData*)data withKey:(NSData*)key andIv:(NSData*)iv;
+ (NSData*)decipherData:(NSData*)data withKey:(NSData*)key andIv:(NSData*)iv;

@end
