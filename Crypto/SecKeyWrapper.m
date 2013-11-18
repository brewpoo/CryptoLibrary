//
//  SecKeyWrapper.m
//  OBTIM
//
//  Created by Jon Lochner on 4/1/13.
//

#import "SecKeyWrapper.h"
#import <Security/SecRandom.h>
#import "NSData+Digest.h"

@implementation SecKeyWrapper

#pragma mark - Key munging
// Taken from http://blog.flirble.org/2011/01/05/rsa-public-key-openssl-ios/
// Deals with the fact that the iOS SecItemAdd does not expect ASN.1 public key header
+ (NSData *)stripPublicKeyHeader:(NSData *)d_key {
    // Skip ASN.1 public key header
    if (d_key == nil) return(nil);
    
    unsigned int len = [d_key length];
    if (!len) return(nil);
    
    unsigned char *c_key = (unsigned char *)[d_key bytes];
    unsigned int  idx    = 0;
    
    if (c_key[idx++] != 0x30) return(nil);
    
    if (c_key[idx] > 0x80) idx += c_key[idx] - 0x80 + 1;
    else idx++;
    
    // PKCS #1 rsaEncryption szOID_RSA_RSA
    static unsigned char seqiod[] =
    { 0x30,   0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
        0x01, 0x05, 0x00 };
    if (memcmp(&c_key[idx], seqiod, 15)) return(nil);
    
    idx += 15;
    
    if (c_key[idx++] != 0x03) return(nil);
    
    if (c_key[idx] > 0x80) idx += c_key[idx] - 0x80 + 1;
    else idx++;
    
    if (c_key[idx++] != '\0') return(nil);
    
    // Now make a new NSData from this buffer
    return([NSData dataWithBytes:&c_key[idx] length:len - idx]);
}

// Helper function for ASN.1 encoding

size_t encodeLength(unsigned char * buf, size_t length) {
    
    // encode length in ASN.1 DER format
    if (length < 128) {
        buf[0] = length;
        return 1;
    }
    
    size_t i = (length / 256) + 1;
    buf[0] = i + 0x80;
    for (size_t j = 0 ; j < i; ++j) {
        buf[i - j] = length & 0xFF;
        length = length >> 8;
    }
    
    return i + 1;
}

// Taken from http://blog.wingsofhermes.org/?p=42
// Adds the header back to the public key
+ (NSData*)exportPublicKey:(SecKeyRef)key {
    OSStatus status = noErr;
    CFDataRef dataRef;

	NSMutableDictionary *namedKeyAttr = [[NSMutableDictionary alloc] init];
	//[namedKeyAttr setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
	[namedKeyAttr setObject:(__bridge id)key forKey:(__bridge id)kSecValueRef];
	[namedKeyAttr setObject:(__bridge id)kCFBooleanTrue forKey:(__bridge id)kSecReturnData];
    
    status = SecItemCopyMatching((__bridge CFDictionaryRef)namedKeyAttr, (CFTypeRef*)&dataRef);
    
    if (status != noErr || dataRef == NULL) {
        NSLog(@"Unable to obtian public key bits. OSStatus: %ld", status);
        return NO;
    }
    
    NSData *publicKeyBits = (NSData*)CFBridgingRelease(dataRef);
    
    static const unsigned char _encodedRSAEncryptionOID[15] = {
        /* Sequence of length 0xd made up of OID followed by NULL */
        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
        0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00
    };

    // OK - that gives us the "BITSTRING component of a full DER
    // encoded RSA public key - we now need to build the rest
    
    unsigned char builder[15];
    NSMutableData * encKey = [[NSMutableData alloc] init];
    int bitstringEncLength;
    
    // When we get to the bitstring - how will we encode it?
    if  ([publicKeyBits length ] + 1  < 128 )
        bitstringEncLength = 1 ;
    else
        bitstringEncLength = (([publicKeyBits length ] +1 ) / 256 ) + 2 ;
    
    // Overall we have a sequence of a certain length
    builder[0] = 0x30;    // ASN.1 encoding representing a SEQUENCE
    // Build up overall size made up of -
    // size of OID + size of bitstring encoding + size of actual key
    size_t i = sizeof(_encodedRSAEncryptionOID) + 2 + bitstringEncLength +
    [publicKeyBits length];
    size_t j = encodeLength(&builder[1], i);
    [encKey appendBytes:builder length:j +1];
    
    // First part of the sequence is the OID
    [encKey appendBytes:_encodedRSAEncryptionOID
                 length:sizeof(_encodedRSAEncryptionOID)];
    
    // Now add the bitstring
    builder[0] = 0x03;
    j = encodeLength(&builder[1], [publicKeyBits length] + 1);
    builder[j+1] = 0x00;
    [encKey appendBytes:builder length:j + 2];
    
    // Now the actual key
    [encKey appendData:publicKeyBits];
    
    return encKey;
}

#pragma mark - Key management functions
+ (BOOL)removeKeyNamed:(NSString*)name {
    OSStatus status = noErr;
    
    if (name==nil) {
        return NO;
    }
    
	NSData *keyTag = [[NSData alloc] initWithBytes:(const void *)[name UTF8String] length:[name length]];
	NSMutableDictionary *namedKeyAttr = [[NSMutableDictionary alloc] init];
    
	[namedKeyAttr setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
	[namedKeyAttr setObject:keyTag forKey:(__bridge id)kSecAttrApplicationTag];
    
	status = SecItemDelete((__bridge CFDictionaryRef) namedKeyAttr);
    
    if (status != errSecSuccess) {
        //LogWarn(@"Problem deleting key from keychain, OSStatus: %ld", status);
        return NO;
    }
    return YES;
}

+ (SecKeyRef)addPublicKey:(NSData *)keyBits withName:(NSString *)name {
    [self removeKeyNamed:name];
    
	OSStatus status = noErr;
	SecKeyRef keyRef = NULL;
    
    if (name == nil || keyBits == nil) {
        return NO;
    }
    
    NSData *keyTag = [[NSData alloc] initWithBytes:(const void *)[name UTF8String] length:[name length]];
	NSMutableDictionary *namedKeyAttr = [[NSMutableDictionary alloc] init];
    
	[namedKeyAttr setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
	[namedKeyAttr setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
	[namedKeyAttr setObject:(__bridge id)kSecAttrKeyClassPublic forKey:(__bridge id)kSecAttrKeyClass];
	[namedKeyAttr setObject:keyTag forKey:(__bridge id)kSecAttrApplicationTag];
	[namedKeyAttr setObject:keyBits forKey:(__bridge id)kSecValueData];
    //[namedKeyAttr setObject:[NSNumber numberWithInt:1024] forKey:(__bridge id)kSecAttrKeySizeInBits];
    [namedKeyAttr setObject:(__bridge id)kCFBooleanTrue forKey:(__bridge id)kSecAttrIsPermanent];
	[namedKeyAttr setObject:(__bridge id)kCFBooleanTrue forKey:(__bridge id)kSecReturnRef];
    
	status = SecItemAdd((__bridge CFDictionaryRef) namedKeyAttr, (CFTypeRef *)&keyRef);
    
    if (status != noErr || keyRef == NULL) {
        NSLog(@"Problem adding public key, OSStatus: %ld", status);
        return nil;
    }
    
    return keyRef;
}

+ (SecKeyRef)addPrivateKey:(NSData *)keyBits withName:(NSString *)name {
    [self removeKeyNamed:name];
    
	OSStatus status = noErr;
	SecKeyRef keyRef = NULL;
    
    if (name == nil || keyBits == nil) {
        return NO;
    }
    
	NSData *keyTag = [[NSData alloc] initWithBytes:(const void *)[name UTF8String] length:[name length]];
	NSMutableDictionary *namedKeyAttr = [[NSMutableDictionary alloc] init];
    
	[namedKeyAttr setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
	[namedKeyAttr setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
	[namedKeyAttr setObject:(__bridge id)kSecAttrKeyClassPrivate forKey:(__bridge id)kSecAttrKeyClass];
	[namedKeyAttr setObject:keyTag forKey:(__bridge id)kSecAttrApplicationTag];
	[namedKeyAttr setObject:keyBits forKey:(__bridge id)kSecValueData];
    //[namedKeyAttr setObject:[NSNumber numberWithInt:1024] forKey:(__bridge id)kSecAttrKeySizeInBits];
    [namedKeyAttr setObject:(__bridge id)kCFBooleanTrue forKey:(__bridge id)kSecAttrIsPermanent];
	[namedKeyAttr setObject:(__bridge id)kCFBooleanTrue forKey:(__bridge id)kSecReturnRef];
    
	status = SecItemAdd((__bridge CFDictionaryRef) namedKeyAttr, (CFTypeRef *)&keyRef);
    
    if (status != noErr) {
        NSLog(@"Problem adding private key, OSStatus: %ld", status);
        return nil;
    }
    return keyRef;
}


+ (SecKeyRef)addSymmetricKey:(NSData *)keyBits withName:(NSString *)name {
    [self removeKeyNamed:name];
    
	OSStatus status = noErr;
	SecKeyRef keyRef = NULL;
    
    if (name == nil || keyBits == nil) {
        return NO;
    }
    
	NSData *keyTag = [[NSData alloc] initWithBytes:(const void *)[name UTF8String] length:[name length]];
	NSMutableDictionary *namedKeyAttr = [[NSMutableDictionary alloc] init];
    
	[namedKeyAttr setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [namedKeyAttr setObject:(__bridge id)kSecAttrKeyClassSymmetric forKey:(__bridge id)kSecAttrKeyClass];
    [namedKeyAttr setObject:[NSNumber numberWithUnsignedInt:0] forKey:(__bridge id)kSecAttrKeyType];
	[namedKeyAttr setObject:keyTag forKey:(__bridge id)kSecAttrApplicationTag];
	[namedKeyAttr setObject:keyBits forKey:(__bridge id)kSecValueData];
    //[namedKeyAttr setObject:(__bridge id)kCFBooleanTrue forKey:(__bridge id)kSecAttrIsPermanent];
	[namedKeyAttr setObject:(__bridge id)kCFBooleanTrue forKey:(__bridge id)kSecReturnRef];
	[namedKeyAttr setObject:(id)kCFBooleanTrue forKey:(__bridge id)kSecAttrCanEncrypt];
	[namedKeyAttr setObject:(id)kCFBooleanTrue forKey:(__bridge id)kSecAttrCanDecrypt];
    
	status = SecItemAdd((__bridge CFDictionaryRef) namedKeyAttr, (CFTypeRef *)&keyRef);
    
    if (status != noErr) {
        NSLog(@"Problem adding key, OSStatus: %ld", status);
        return nil;
    }
    return keyRef;
}

+ (SecCertificateRef)addCertificate:(NSData*)certificate withName:(NSString*)name {
    OSStatus status = noErr;
    SecCertificateRef certRef;
    
    if (name == nil || certificate == nil) {
        return NO;
    }
    
    certRef = SecCertificateCreateWithData(NULL, (__bridge CFDataRef) certificate);
    
    NSData *certTag = [[NSData alloc] initWithBytes:(const void *)[name UTF8String] length:[name length]];
	NSMutableDictionary *namedCertAttr = [[NSMutableDictionary alloc] init];
    
	[namedCertAttr setObject:certTag forKey:(__bridge id)kSecAttrLabel];
	[namedCertAttr setObject:(__bridge id)certRef forKey:(__bridge id)kSecValueRef];
    
    status = SecItemAdd((__bridge CFDictionaryRef) namedCertAttr, NULL);
    
    if (status != errSecSuccess && status != errSecDuplicateItem) {
        NSLog(@"Problem adding certificate, OSStatus: %ld", status);
        return nil;
    }
    return certRef;
}

+ (SecIdentityRef)addIdentity:(NSData*)identity withName:(NSString*)name andPassword:(NSString*)password {
    OSStatus status = noErr;
    
    if (name == nil || identity == nil) {
        return NO;
    }
    
    CFArrayRef importedItems = NULL;
    NSData *identityTag = [[NSData alloc] initWithBytes:(const void*)[name UTF8String] length:[name length]];
    NSMutableDictionary *pkcsOptions = [[NSMutableDictionary alloc] init];
    [pkcsOptions setObject:password forKey:(__bridge id<NSCopying>)(kSecImportExportPassphrase)];
    
    status = SecPKCS12Import((__bridge CFDataRef)identity, (__bridge CFDictionaryRef)pkcsOptions, &importedItems);
    
    if (status != noErr) {
        NSLog(@"Problem decoding pkcs12, OSStatus: %ld", status);
        return NO;
    }
    
    // +++ If there are multiple identities in the PKCS#12, and adding a non-first
    // one fails, we end up with partial results.  Right now that's not an issue
    // in practice, but I might want to revisit this.
    
    SecIdentityRef identityRef = NULL;

    for (NSDictionary * itemDict in (__bridge id) importedItems) {
        identityRef = (__bridge SecIdentityRef) [itemDict objectForKey:(__bridge NSString *) kSecImportItemIdentity];
        NSMutableDictionary *namedIdentityAttr = [[NSMutableDictionary alloc] init];
        [namedIdentityAttr setObject:(__bridge id)identityRef forKey:(__bridge id)kSecValueRef];
        [namedIdentityAttr setObject:identityTag forKey:(__bridge id)kSecAttrLabel];
        status = SecItemAdd((__bridge CFDictionaryRef)(namedIdentityAttr),NULL);
        if (status == errSecDuplicateItem) {
            status = noErr;
        }
        if (status != noErr) {
            break;
        }
    }
    
    CFRelease(importedItems);

    if (status != noErr) {
        NSLog(@"Problem adding identity, OSStatus: %ld", status);
        return nil;
    }
    return identityRef;
}

#pragma mark - Security reference getters
+ (SecKeyRef)getKeyRefFor:(NSString*)keyName {
    OSStatus status = noErr;
	SecKeyRef keyRef = NULL;
    
    if (keyName == nil) {
        return nil;
    }
    
	NSData *keyTag = [[NSData alloc] initWithBytes:(const void *)[keyName UTF8String] length:[keyName length]];
	NSMutableDictionary *namedKeyAttr = [[NSMutableDictionary alloc] init];
    
	[namedKeyAttr setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
	[namedKeyAttr setObject:keyTag forKey:(__bridge id)kSecAttrApplicationTag];
	[namedKeyAttr setObject:(__bridge id)kCFBooleanTrue forKey:(__bridge id)kSecReturnRef];
    
    status = SecItemCopyMatching((__bridge CFDictionaryRef)namedKeyAttr, (CFTypeRef*)&keyRef);
    
    if (status != noErr || keyRef == NULL) {
        NSLog(@"Unable to load key. OSStatus: %ld", status);
        return NO;
    }
    return keyRef;
}

+ (SecCertificateRef)getCertRefFor:(NSString*)certName {
    OSStatus status = noErr;
	SecCertificateRef certRef = NULL;
    
    if (certName == nil) {
        return nil;
    }
    
	NSData *certTag = [[NSData alloc] initWithBytes:(const void *)[certName UTF8String] length:[certName length]];
	NSMutableDictionary *namedCertAttr = [[NSMutableDictionary alloc] init];
    
	[namedCertAttr setObject:(__bridge id)kSecClassCertificate forKey:(__bridge id)kSecClass];
	[namedCertAttr setObject:certTag forKey:(__bridge id)kSecAttrLabel];
	[namedCertAttr setObject:(__bridge id)kCFBooleanTrue forKey:(__bridge id)kSecReturnRef];
    
    status = SecItemCopyMatching((__bridge CFDictionaryRef)namedCertAttr, (CFTypeRef*)&certRef);
    
    if (status != noErr || certRef == NULL) {
        NSLog(@"Unable to load cert. OSStatus: %ld", status);
        return NO;
    }
    return certRef;
}

+ (SecIdentityRef)getIdentifyRefFor:(NSString*)identityName {
    OSStatus status = noErr;
    SecIdentityRef identityRef = NULL;
    
    if (identityName == nil) {
        return nil;
    }
    
	NSMutableDictionary *namedIdentityAttr = [[NSMutableDictionary alloc] init];
    
	[namedIdentityAttr setObject:(__bridge id)kSecClassIdentity forKey:(__bridge id)kSecClass];
	[namedIdentityAttr setObject:(__bridge id)kCFBooleanTrue forKey:(__bridge id)kSecReturnRef];
    
    status = SecItemCopyMatching((__bridge CFDictionaryRef)namedIdentityAttr, (CFTypeRef*)&identityRef);
    
    if (status != noErr || identityRef == NULL) {
        NSLog(@"Unable to load identity. OSStatus: %ld", status);
        return nil;
    }
    
    return identityRef;
}

#pragma mark - Key chain dumper
+ (void)enumerateKeychain {
    NSMutableDictionary *query = [NSMutableDictionary dictionaryWithObjectsAndKeys:
                                  (__bridge id)kCFBooleanTrue, (__bridge id)kSecReturnAttributes,
                                  (__bridge id)kSecMatchLimitAll, (__bridge id)kSecMatchLimit,
                                  nil];
    NSArray *secItemClasses = [NSArray arrayWithObjects:
                               (__bridge id)kSecClassGenericPassword,
                               (__bridge id)kSecClassInternetPassword,
                               (__bridge id)kSecClassCertificate,
                               (__bridge id)kSecClassKey,
                               (__bridge id)kSecClassIdentity,
                               nil];
    for (id secItemClass in secItemClasses) {
        [query setObject:secItemClass forKey:(__bridge id)kSecClass];
        
        CFTypeRef result = NULL;
        SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
        NSLog(@"%@", (__bridge id)result);
        if (result != NULL) CFRelease(result);
    }
}

+ (void)describeKeyRef:(SecKeyRef)keyRef {
    NSMutableDictionary *query = [NSMutableDictionary dictionaryWithObjectsAndKeys:
                                  (__bridge id)kCFBooleanTrue, (__bridge id)kSecReturnAttributes,
                                  (__bridge id)keyRef, (__bridge id)kSecValueRef,
                                  nil];
    CFTypeRef result = NULL;
    SecItemCopyMatching((__bridge CFDictionaryRef)(query), &result);
    NSLog(@"keyRef details: %@", (__bridge id)result);
    if (result != NULL) CFRelease(result);
}

+ (void)removeAll {
    NSMutableDictionary *query = [NSMutableDictionary dictionaryWithObjectsAndKeys:
                                  (__bridge id)kCFBooleanTrue, (__bridge id)kSecReturnAttributes,
                                  (__bridge id)kSecMatchLimitAll, (__bridge id)kSecMatchLimit,
                                  nil];
    NSArray *secItemClasses = [NSArray arrayWithObjects:
                               (__bridge id)kSecClassGenericPassword,
                               (__bridge id)kSecClassInternetPassword,
                               (__bridge id)kSecClassCertificate,
                               (__bridge id)kSecClassKey,
                               (__bridge id)kSecClassIdentity,
                               nil];
    for (id secItemClass in secItemClasses) {
        [query setObject:secItemClass forKey:(__bridge id)kSecClass];
        SecItemDelete((__bridge CFDictionaryRef)query);
    }
}

+ (void)removeAll:(CFTypeRef)keyRefClass {
    NSMutableDictionary *query = [NSMutableDictionary dictionaryWithObjectsAndKeys:
                                  (__bridge id)kCFBooleanTrue, (__bridge id)kSecReturnAttributes,
                                  (__bridge id)kSecMatchLimitAll, (__bridge id)kSecMatchLimit,
                                  (__bridge id)keyRefClass, (__bridge id)kSecClass,
                                  nil];
    SecItemDelete((__bridge CFDictionaryRef)(query));
}

#pragma mark - Key generators
+ (BOOL)generateKeypairNamed:(NSString*)name {
    OSStatus status = noErr;
    
    NSMutableDictionary *privateKeyAttr = [[NSMutableDictionary alloc] init];
    NSMutableDictionary *publicKeyAttr = [[NSMutableDictionary alloc] init];
    NSMutableDictionary *keyPairAttr = [[NSMutableDictionary alloc] init];
    
    NSString *publicName = [name stringByAppendingString:@".public"];
    NSString *privateName = [name stringByAppendingString:@".private"];
    
    
    NSData *publicTag = [NSData dataWithBytes:(const void *)[publicName UTF8String]
                                       length:[publicName length]];
    NSData *privateTag = [NSData dataWithBytes:(const void *)[privateName UTF8String]
                                        length:[privateName length]];
    
    SecKeyRef publicKeyRef = NULL;
    SecKeyRef privateKeyRef = NULL;
    
    [keyPairAttr setObject:(__bridge id)kSecAttrKeyTypeRSA
                    forKey:(__bridge id)kSecAttrKeyType];
    [keyPairAttr setObject:[NSNumber numberWithInt:2048]
                    forKey:(__bridge id)kSecAttrKeySizeInBits];
    
    [privateKeyAttr setObject:[NSNumber numberWithBool:YES]
                       forKey:(__bridge id)kSecAttrIsPermanent];
    [privateKeyAttr setObject:privateTag
                       forKey:(__bridge id)kSecAttrApplicationTag];
    
    [publicKeyAttr setObject:[NSNumber numberWithBool:YES]
                      forKey:(__bridge id)kSecAttrIsPermanent];
    [publicKeyAttr setObject:publicTag
                      forKey:(__bridge id)kSecAttrApplicationTag];
    
    [keyPairAttr setObject:privateKeyAttr
                    forKey:(__bridge id)kSecPrivateKeyAttrs];
    [keyPairAttr setObject:publicKeyAttr
                    forKey:(__bridge id)kSecPublicKeyAttrs];
    
    status = SecKeyGeneratePair((__bridge CFDictionaryRef)keyPairAttr,
                                &publicKeyRef, &privateKeyRef);
    
    if (status != noErr) {
        NSLog(@"Error generating keypair. OSStatus: %ld", status);
        return NO;
    }
    
    if(publicKeyRef) CFRelease(publicKeyRef);
    if(privateKeyRef) CFRelease(privateKeyRef);
    
    return YES;
}

+ (BOOL)generateSymmetricKeyNamed:(NSString*)name {
    [self removeKeyNamed:name];
    OSStatus status = noErr;
    
    NSMutableDictionary *namedKeyAttr = [[NSMutableDictionary alloc] init];
    
    NSData *namedTag = [NSData dataWithBytes:(const void *)[name UTF8String]
                                      length:[name length]];
    
    SecKeyRef keyRef = NULL;
    
    uint8_t data[256];
    int err = 0;
    err = SecRandomCopyBytes(kSecRandomDefault, 256, data);
    if (err != noErr) {
        return NO;
    }
    
    [namedKeyAttr setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [namedKeyAttr setObject:(__bridge id)kSecAttrKeyClassSymmetric forKey:(__bridge id)kSecAttrKeyClass];
    [namedKeyAttr setObject:[NSNumber numberWithInt:kCCAlgorithmAES128] forKey:(__bridge id)(kSecAttrKeyType)];
    
	[namedKeyAttr setObject:namedTag forKey:(__bridge id)kSecAttrApplicationTag];
	[namedKeyAttr setObject:[NSData dataWithBytes:data length:sizeof(data)]forKey:(__bridge id)kSecValueData];
    [namedKeyAttr setObject:[NSNumber numberWithInt:sizeof(data)*8] forKey:(__bridge id)kSecAttrKeySizeInBits];
    
    [namedKeyAttr setObject:(__bridge id)kCFBooleanTrue forKey:(__bridge id)kSecAttrIsPermanent];
	[namedKeyAttr setObject:(__bridge id)kCFBooleanTrue forKey:(__bridge id)kSecReturnRef];
    
    status = SecItemAdd((__bridge CFDictionaryRef)namedKeyAttr,
                        (CFTypeRef*)&keyRef);
    
    if (status != noErr) {
        NSLog(@"Error symmetric key. OSStatus: %ld", status);
        return NO;
    }
    
    if(keyRef) CFRelease(keyRef);
    
    return YES;
}

#pragma mark - Asymmetric Encryption/decryption
+ (NSData*)encryptData:(NSData*)rawData withKey:(SecKeyRef)key {
    OSStatus status = noErr;
    
    uint8_t* plainText = (uint8_t *)[rawData bytes];
        
    size_t cipherTextSize = 256;
    uint8_t *cipherTextBuf = NULL;
    
    cipherTextBuf = malloc(cipherTextSize);
    memset(cipherTextBuf, 0, cipherTextSize);
    
    
    status = SecKeyEncrypt(key, kSecPaddingPKCS1, plainText, [rawData length], cipherTextBuf, &cipherTextSize);
        
    if (status != noErr) {
        NSLog(@"Error encrypting data. OSStatus: %ld", status);
        free(cipherTextBuf);
        return nil;
    }
    
    NSData *encryptedData = [NSData dataWithBytes:cipherTextBuf length:[rawData length]];
    free(cipherTextBuf);
    
    return encryptedData;
}

+ (NSData*)decryptData:(NSData*)cipherData withKey:(SecKeyRef)key {
    OSStatus status = noErr;
    
    size_t cipherBufferSize = [cipherData length];
    uint8_t *cipherBuffer = (uint8_t *)[cipherData bytes];
    
    size_t plainBufferSize;
    uint8_t *plainBuffer;
    
    plainBufferSize = SecKeyGetBlockSize(key);
    plainBuffer = malloc(plainBufferSize);
    
    status = SecKeyDecrypt(key, kSecPaddingPKCS1, cipherBuffer, cipherBufferSize, plainBuffer, &plainBufferSize);
        
    if (status != noErr) {
        NSLog(@"Error decrypting data. OSStatus: %ld", status);
        free(plainBuffer);
        return nil;
    }
    
    NSData *decryptedData = [NSData dataWithBytes:plainBuffer length:[cipherData length]];
    free(plainBuffer);
    
    return decryptedData;
}

#pragma mark - Symmetric Key Encryption (AES128)
+ (NSData *)cipherData:(NSData *)dataIn usingKey:(NSData *)key andIv:(NSData *)iv withOperation:(CCOperation)encryptOrDecrypt {
    CCCryptorStatus ccStatus   = kCCSuccess;
    size_t          cryptBytes = 0;    // Number of bytes moved to buffer.
    NSMutableData  *dataOut    = [NSMutableData dataWithLength:dataIn.length + kCCBlockSizeAES128];
    
    ccStatus = CCCrypt( encryptOrDecrypt,
                       kCCAlgorithmAES128,
                       kCCOptionPKCS7Padding,
                       key.bytes,
                       kCCKeySizeAES128,
                       iv.bytes,
                       dataIn.bytes,
                       dataIn.length,
                       dataOut.mutableBytes,
                       dataOut.length,
                       &cryptBytes);
    
    if (ccStatus != kCCSuccess) {
        NSLog(@"CCCrypt status: %d", ccStatus);
    }
    
    dataOut.length = cryptBytes;
    
    return dataOut;
}


+ (NSData*)encipherData:(NSData *)data withKey:(NSData *)key andIv:(NSData *)iv {
    return [self cipherData:data usingKey:key andIv:iv withOperation:kCCEncrypt];
}

+ (NSData*)decipherData:(NSData *)data withKey:(NSData *)key andIv:(NSData *)iv {
    return [self cipherData:data usingKey:key andIv:iv withOperation:kCCDecrypt];
}

#pragma mark - Digitial signature
+ (NSData *)signData:(NSData*)rawData usingKey:(SecKeyRef)key {
    OSStatus status = noErr;
        
    NSData *digest = [rawData sha1Digest]; // Generate SHA1 digest
	NSData * signedHash = nil;
	
	uint8_t * signedHashBytes = NULL;
	size_t signedHashBytesSize = 0;
		
	signedHashBytesSize = SecKeyGetBlockSize(key);
	
	// Malloc a buffer to hold signature.
	signedHashBytes = malloc( signedHashBytesSize * sizeof(uint8_t) );
	memset((void *)signedHashBytes, 0x0, signedHashBytesSize);
	
	// Sign the SHA1 hash.
	status = SecKeyRawSign(key, kSecPaddingPKCS1SHA1, (const uint8_t *)[digest bytes], CC_SHA1_DIGEST_LENGTH, (uint8_t *)signedHashBytes, &signedHashBytesSize);
    if (status != noErr) {
        NSLog(@"Error encrypting data. OSStatus: %ld", status);
        free(signedHashBytes);
        return nil;
    }
    
	// Build up signed SHA1 blob.
	signedHash = [NSData dataWithBytes:(const void *)signedHashBytes length:(NSUInteger)signedHashBytesSize];
	
	if (signedHashBytes) free(signedHashBytes);
	
	return signedHash;
}

+ (BOOL)verifySignature:(NSData*)signedHash ofData:(NSData*)data usingKey:(SecKeyRef)key {
	size_t signedHashBytesSize = 0;
	OSStatus status = noErr;
	
	// Get the size of the assymetric block.
	signedHashBytesSize = [signedHash length];
	
	status = SecKeyRawVerify(key, kSecPaddingPKCS1SHA1, (const uint8_t *)[[data sha1Digest] bytes], CC_SHA1_DIGEST_LENGTH, (const uint8_t *)[signedHash bytes], signedHashBytesSize);
	
	return (status == noErr) ? YES : NO;
}

@end
