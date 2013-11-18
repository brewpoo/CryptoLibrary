//
//  SecKeyWrapperTests.m
//  OBTIM
//
//  Created by Jon Lochner on 4/1/13.
//

#import "SecKeyWrapperTests.h"
#import "SecKeyWrapper.h"

#define EXP_SHORTHAND
#import "Expecta.h"
#import "NSData+Digest.h"
#import "Base64.h"

@implementation SecKeyWrapperTests

NSString* const certificateDer = @"MIIDKDCCAhACCQDjEiG3Y4L8ZjANBgkqhkiG9w0BAQUFADBWMQswCQYDVQQGEwJVUzELMAkGA1UECBMCTlkxDTALBgNVBAcTBFRlc3QxDTALBgNVBAoTBFRlc3QxDTALBgNVBAsTBFRlc3QxDTALBgNVBAMTBFRlc3QwHhcNMTMwNDAyMTQxNzAwWhcNMTQwNDAyMTQxNzAwWjBWMQswCQYDVQQGEwJVUzELMAkGA1UECBMCTlkxDTALBgNVBAcTBFRlc3QxDTALBgNVBAoTBFRlc3QxDTALBgNVBAsTBFRlc3QxDTALBgNVBAMTBFRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC36Wa0TTAe+LDnmPJnE1vgWd9Qj58A0bctbfKbpGhrNQgatFjPzOM6ctRL8E+0/mgOI9dmmY9NDcdxZWhxoe2DzJnBPmngkqhSFv43G2BxWunmSNonFYZRUSUKMifBqThnJgKS3PxaSOjvQKte6ORLOQpmSWA5JbEWUbv2hWy7tFkoUA2d8orxK+2/XZftaMihciQljcFmKwNGV5fqZnT2hnLmTbnVW99arXB49fyrBs2xi4NxSN5o3eV3VUJWro/aP775ng+e0/kglIihi34J4K9zvdCq1M0X2v/sQJcs/khCkrFBi17QQnrUtsMIw8sC9Vky9THn49O2AIBpCH+7AgMBAAEwDQYJKoZIhvcNAQEFBQADggEBAGZe4Y73t/8tcj5RF2wWR2uPZ8suLzGOg4CNWgzKXWz2aI377BDFKpffcEOohOuFtUyTD9ZOuSa6WHKRDg/laQ0BU8RT/h8xSNMWZfzzjZfdv9MfHr5rhpy6q7Fkb/JVjuYRkQ8rtDdaXICDQCzGi34vIeqiPDsFUMTWwBcCz978wBnwiuBcMzTFYxmD2GfscMxPoQfHmlyQ8Q2jx9midgKcMfdqXqE03ykjTb0kvc26vDkjAQ5zziBs4w/md7ej1kEB427v3/5GXw5NQQ8+GrY8r/Gbow6cPGG3vhOQq+1eu3z8l/+l5SrrXJGTFC/tDiwqo12ttGoKjA/JvQ6+DGY=";

NSString* const keyData = @"MIICXAIBAAKBgQCV+3npCWdrRYtaRPmhTSEk/aP4pYJn7PflLSu1gLVNW2Z9TCvJxBcozn6TyrbGeKy9EztE5Y3PIbb0u0VSHNz2AxJ6zJ4Kim97M5WDq//GkAh0G+lh74KAlyVNhrql6AREiLGJhVqMK1ILfOt/9zehcyJv+4Xq02pIdexwk9/DmQIDAQABAoGAdJKDTMeMZGonR8A4rlB+pHuoCMjLtO8QNkaHpIknYbrazCR6HFaXEZZ9920l5tlAmazq8j/hms6/nzQ3Sv04F6XpRTbIPfZw5TlvlqNk9j/3hXgRl8O3Aw83q2hyfs7f7iqovDjA7OA2iil3V0N0+WhVo6YFlWVUlp7KMYo8S6ECQQDGClelIP7S16BpZzYM3hBv24eXoBG5Gpkro/E24ZPavte/pSnSPIyG+ca6QYV8ojYVvf+kvuTh6315p3l0jPXFAkEAweCCR+B9rUlBDSjYS9uIuo5++m+HnAWgkPQLWNWbRGO5i5G4xy8jXn2B3PDgqanUWwPTE2/KLEQfeIqPTxlHxQJADXu6x+VdNCG2LDb4uRuNZvA9ZRdi3YVwFEaPL7tgA66mpceq90NkFfR/kULQwdGReR18gEz27GLKIjRC0qqeOQJBAJK+H13P6M/0FiyjsbMY4xBxMmLTb80D5VhRnxUJ+I92+8VL8pOwdhDa5iQYnbNNO9H3vxeDEX8XwMo39ehkthECQE1NchwjEFz5APFeI/yv29r7m0pz6te+dg+ll73uQHLpGfgOguDuaIgDe6YTwAALVdVXVyxR2q90cjXQREE2GlY=";

- (void)setUp {
    [SecKeyWrapper removeAll];
}

- (NSData*)dataWithDEADBEEFLength:(NSUInteger)length {
    uint8_t item_bytes[] = { 0xDE, 0xAD, 0xBE, 0xEF };
    NSMutableData *returnValue = [[NSMutableData alloc] initWithLength:length];
    uint8_t *bytes = [returnValue mutableBytes];
    for (NSUInteger i = 0; i < length; i++)
    {
        bytes[i] = item_bytes[i % 4];
    }
    return returnValue;
}

- (NSData*)generateAES128Key {
    uint8_t data[16];
    int err = 0;
    err = SecRandomCopyBytes(kSecRandomDefault, 16, data);
    return [NSData dataWithBytes:data length:(16)];
}

- (void)testRemoveMissingKey {
    expect([SecKeyWrapper removeKeyNamed:@"test"]).to.beFalsy();
}

- (void)testRemovingKey {
    [SecKeyWrapper addPublicKey:[keyData base64DecodedData] withName:@"test-read"];
    expect([SecKeyWrapper removeKeyNamed:@"test-read"]).to.beTruthy();
}

- (void)testGeneratingKeyPair {
    expect([SecKeyWrapper generateKeypairNamed:@"test"]).to.beTruthy();
    SecKeyRef privateKeyRef = [SecKeyWrapper getKeyRefFor:@"test.private"];
    SecKeyRef publicKeyRef = [SecKeyWrapper getKeyRefFor:@"test.public"];
    
    expect(privateKeyRef).toNot.beNil();
    expect(publicKeyRef).toNot.beNil();
}

- (void)testStoringKeyMaterial {
    expect([SecKeyWrapper addPrivateKey:[keyData base64DecodedData] withName:@"test-write"]).to.beTruthy();
    SecKeyRef keyRef = [SecKeyWrapper getKeyRefFor:@"test-write"];
    expect(keyRef).toNot.beNil();
}

- (void)testReadingKeyMaterial {
    uint8_t data[256];
    int err = 0;
    err = SecRandomCopyBytes(kSecRandomDefault, 256, data);
    
    NSData *item1 = [self dataWithDEADBEEFLength:4];
    NSData *item2 = [self dataWithDEADBEEFLength:4];
    
    NSMutableArray *testArray = [[NSMutableArray alloc] init];
    [testArray addObject:item1];
    [testArray addObject:item2];
    NSData *testData = [testArray berData];
    
    
    [SecKeyWrapper addPublicKey:testData withName:@"readme"];
    SecKeyRef keyRef = [SecKeyWrapper getKeyRefFor:@"readme"];
    //[SecKeyWrapper enumerateKeychain];
    expect(keyRef).toNot.beNil();
}

- (void)testSymmetricalEncryption {
    NSData *key = [self generateAES128Key];
    NSData *clearText = [@"In the clear" dataUsingEncoding:NSUTF8StringEncoding];
    NSData *cipherData = [SecKeyWrapper encipherData:clearText withKey:key andIv:nil];
    expect(cipherData).toNot.beNil();
}

- (void)testSymmetricalRoundTrip {
    NSData *key = [self generateAES128Key];
    NSData *clearData = [@"This is secret data" dataUsingEncoding:NSUTF8StringEncoding];
    NSLog(@"Clear Text: %@", [clearData description]);
    NSData *cipherData = [SecKeyWrapper encipherData:clearData withKey:key andIv:nil];
    NSData *decipherData =[SecKeyWrapper decipherData:cipherData withKey:key andIv:nil];
    NSLog(@"Decipher Text: %@", [decipherData description]);
    expect([decipherData isEqualToData:clearData]).to.beTruthy();
}

- (void)testAddCertificate {
    expect([SecKeyWrapper addCertificate:[certificateDer base64DecodedData] withName:@"test-certificate"]).to.beTruthy();
//    SecCertificateRef cert = [SecKeyWrapper getCertRefFor:@"test-certificate"];
//    expect(cert).toNot.beNil();
}

- (void)testAddIdentity {
    NSString *filePath = [[NSBundle bundleForClass:[self class]] pathForResource:@"sample" ofType:@"p12"];
    NSData *identity = [NSData dataWithContentsOfFile:filePath];
    expect([SecKeyWrapper addIdentity:identity withName:@"test-identity" andPassword:@""]).to.beTruthy();
   // SecIdentityRef identityRef = [SecKeyWrapper getIdentifyRefFor:@"test-identity"];
   // expect(identityRef).toNot.beNil();
}

- (void)testSignedHash {
    [SecKeyWrapper generateKeypairNamed:@"test-signing"];
    SecKeyRef privateKey = [SecKeyWrapper getKeyRefFor:@"test-signing.private"];
    SecKeyRef publicKey = [SecKeyWrapper getKeyRefFor:@"test-signing.public"];
    expect(privateKey).toNot.beNil();
    NSData *clearData = [@"This is going to be signed" dataUsingEncoding:NSUTF8StringEncoding];
    NSData *signature = [SecKeyWrapper signData:clearData usingKey:privateKey];
    expect(signature).toNot.beNil();
    NSLog(@"Signature: %@", [signature hex]);
    NSLog(@"Signature length: %d", [signature length]);
    expect([SecKeyWrapper verifySignature:signature ofData:clearData usingKey:publicKey]).to.beTruthy();
    NSLog(@"Private key");
    [SecKeyWrapper describeKeyRef:privateKey];
    NSLog(@"Public key");
    [SecKeyWrapper describeKeyRef:publicKey];
}

- (void)testSignedHashWithTamperedData {
    [SecKeyWrapper generateKeypairNamed:@"test-signing"];
    SecKeyRef privateKey = [SecKeyWrapper getKeyRefFor:@"test-signing.private"];
    SecKeyRef publicKey = [SecKeyWrapper getKeyRefFor:@"test-signing.public"];
    expect(privateKey).toNot.beNil();
    NSData *clearData = [@"This is going to be signed" dataUsingEncoding:NSUTF8StringEncoding];
    NSData *signature = [SecKeyWrapper signData:clearData usingKey:privateKey];
    NSData *tamperedData = [@"This is not going to be signed" dataUsingEncoding:NSUTF8StringEncoding];
    expect(signature).toNot.beNil();
    NSLog(@"Signature: %@", [signature hex]);
    expect([SecKeyWrapper verifySignature:signature ofData:tamperedData usingKey:publicKey]).to.beFalsy();
}

@end
