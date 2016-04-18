/*
	This file is part of ios-csr.
	Copyright (C) 2013-14 Ales Teska

	ios-csr is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	ios-csr is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with ios-csr.  If not, see <http://www.gnu.org/licenses/>.
*/

#import "SCCSR.h"
#import <CommonCrypto/CommonDigest.h>

/*

Certification Request Syntax Specification: http://www.ietf.org/rfc/rfc2986.txt

*/

static uint8_t OBJECT_commonName[5] = {0x06, 0x03, 0x55, 0x04, 0x03};
static uint8_t OBJECT_countryName[5] = {0x06, 0x03, 0x55, 0x04, 0x06};
static uint8_t OBJECT_organizationName[5] = {0x06, 0x03, 0x55, 0x04, 0x0A};
static uint8_t OBJECT_organizationalUnitName[5] = {0x06, 0x03, 0x55, 0x04, 0x0B};

static uint8_t OBJECT_rsaEncryptionNULL[13] = {0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00};

// See: http://oid-info.com/get/1.2.840.113549.1.1.11
static uint8_t SEQUENCE_OBJECT_sha256WithRSAEncryption[] = {0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 1, 1, 11, 0x05, 0x00};

static uint8_t SEQUENCE_tag = 0x30;
static uint8_t SET_tag = 0x31;

static OSStatus ItemGetAttributeContent(CFStringRef itemClass, id item, const CFTypeRef attribute, __autoreleasing id* attributeContent)
{
    if (attributeContent)
        *attributeContent = nil;
    
    NSDictionary* itemQuery = [NSDictionary dictionaryWithObjectsAndKeys:
                               (__bridge id _Nonnull)(itemClass), kSecClass,
                               item, kSecValueRef,
                               kCFBooleanTrue, kSecReturnAttributes, nil];
    CFDictionaryRef itemAttrs = NULL;
    OSStatus status = SecItemCopyMatching((CFDictionaryRef) itemQuery, (CFTypeRef*) &itemAttrs);
    if (status == noErr) {
        NSDictionary* attrs = CFBridgingRelease(itemAttrs);
        if (attributeContent)
            *attributeContent = [attrs objectForKey:(__bridge id)attribute];
    }
    return status;
}

///

@implementation SCCSR

@synthesize countryName;
@synthesize organizationName;
@synthesize organizationalUnitName;
@synthesize commonName;
@synthesize subjectDER;

+ (NSError*)errorWithPOSIXError:(int)error
{
    char strerror_buf[256];
    (void) strerror_r(error, strerror_buf, sizeof(strerror_buf));
    NSString* errorString = [NSString stringWithCString:strerror_buf encoding:NSASCIIStringEncoding];
    NSDictionary* userInfo = @{ NSLocalizedDescriptionKey: errorString };
    return [NSError errorWithDomain:NSPOSIXErrorDomain
                               code:error
                           userInfo:userInfo];
}

+ (NSError*)errorWithSecurityStatus:(OSStatus)status
{
    if (status < 0) {
        NSDictionary* userInfo = nil;
        CFStringRef errorString = SecCopyErrorMessageString(status, NULL);
        if (errorString)
            userInfo = @{ NSLocalizedDescriptionKey: CFBridgingRelease(errorString) };
        return [NSError errorWithDomain:NSOSStatusErrorDomain
                                   code:status
                               userInfo:userInfo];
    }
    
    if (status > errSecErrnoBase && status <= errSecErrnoLimit)
        return [self errorWithPOSIXError:status - errSecErrnoBase];
    
    return [NSError errorWithDomain:NSOSStatusErrorDomain
                               code:status
                           userInfo:nil];
}

-(NSData *) buildWithCertificate:(SecCertificateRef)certificate error:(NSError* __autoreleasing*)error
{
    SecIdentityRef identity = NULL;
    NSData* signingRequest = nil;
    OSStatus status = SecIdentityCreateWithCertificate(NULL, certificate, &identity);
    if (status != noErr)
        goto bail;
    
    signingRequest = [self buildWithIdentity:identity error:error];

bail:
    if (identity != NULL)
        CFRelease(identity);
    
    if (status != noErr) {
        if (error != NULL)
            *error = [SCCSR errorWithSecurityStatus:status];
        return nil;
    }
    return signingRequest;
}

-(NSData *) buildWithIdentity:(SecIdentityRef)identity error:(NSError* __autoreleasing*)error
{
    if (error != NULL)
        *error = nil;
    
    OSStatus status = noErr;
    CFErrorRef cfError = NULL;
    SecCertificateRef certificate = NULL;
    SecKeyRef privateKey = NULL;
    NSData* signingRequest = nil;
    NSData* keyBits;
    NSDictionary* certificateValues;
    
    status = SecIdentityCopyCertificate(identity, &certificate);
    if (status != noErr)
        goto bail;
    
    subjectDER = CFBridgingRelease(SecCertificateCopyNormalizedSubjectContent(certificate, &cfError));
    if (subjectDER == nil) {
        if (error != NULL)
            *error = CFBridgingRelease(cfError);
        else
            CFRelease(cfError);
        goto bail;
    }
    
    certificateValues = CFBridgingRelease(SecCertificateCopyValues(certificate, (CFArrayRef) @[ (id)kSecOIDX509V1SubjectPublicKey ], &cfError));
    if (certificateValues == nil) {
        if (error != NULL)
            *error = CFBridgingRelease(cfError);
        else
            CFRelease(cfError);
        goto bail;
    }
    
    keyBits = [(NSDictionary*)[certificateValues objectForKey:(id)kSecOIDX509V1SubjectPublicKey] objectForKey:(id)kSecPropertyKeyValue];
    if (keyBits == nil || ![keyBits isKindOfClass:[NSData class]]) {
        status = errSecDecode;
        goto bail;
    }
    
    status = SecIdentityCopyPrivateKey(identity, &privateKey);
    if (status != noErr)
        goto bail;
    
    signingRequest = [self build:keyBits privateKey:privateKey error:error];
    
bail:
    if (certificate != NULL)
        CFRelease(certificate);
    if (privateKey != NULL)
        CFRelease(privateKey);
    
    if (status != noErr) {
        if (error != NULL)
            *error = [SCCSR errorWithSecurityStatus:status];
        return nil;
    }
    return signingRequest;
}

-(NSData *) buildWithPrivateKey:(SecKeyRef)privateKey error:(NSError* __autoreleasing*)error
{
    return [self build:nil privateKey:privateKey error:error];
}

-(NSData *) build:(NSData *)publicKeyBits privateKey:(SecKeyRef)privateKey error:(NSError* __autoreleasing*)error
{
    if (error != NULL)
        *error = nil;
    
    OSStatus status;
    if (publicKeyBits == nil) {
        NSData* privateLabel = nil;
        status = ItemGetAttributeContent(kSecClassKey, (__bridge id)privateKey, kSecAttrApplicationLabel, &privateLabel);
        if (status != noErr) {
            if (error != NULL)
                *error = [SCCSR errorWithSecurityStatus:status];
            return nil;
        }
        
        NSDictionary* itemQuery = [NSDictionary dictionaryWithObjectsAndKeys:
                                   (id)kSecClassKey, kSecClass,
                                   (id)kSecAttrKeyClassPublic, kSecAttrKeyClass,
                                   (id)kSecAttrKeyTypeRSA, kSecAttrKeyType,
                                   privateLabel, kSecAttrApplicationLabel,
                                   kCFBooleanTrue, kSecReturnRef, nil];
        SecKeyRef publicKey = NULL;
        status = SecItemCopyMatching((CFDictionaryRef) itemQuery, (CFTypeRef*) &publicKey);
        if (status != noErr) {
            if (error != NULL)
                *error = [SCCSR errorWithSecurityStatus:status];
            return nil;
        }

        CFDataRef publicData = NULL;
        status = SecItemExport(publicKey, kSecFormatBSAFE, 0, NULL, &publicData);
        if (status != noErr) {
            if (error != NULL)
                *error = [SCCSR errorWithSecurityStatus:status];
            return nil;
        }

        publicKeyBits = CFBridgingRelease(publicData);
    }
    
	NSMutableData * certificationRequestInfo = [self buildCertificationRequestInfo:publicKeyBits];

#if TARGET_OS_IPHONE
    // Build signature - step 1: SHA256 hash
    CC_SHA256_CTX SHA256;
    CC_SHA256_Init(&SHA256);
    CC_SHA256_Update(&SHA256, [certificationRequestInfo bytes], (unsigned int)[certificationRequestInfo length]);
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256_Final(digest, &SHA256);
    
    // Build signature - step 2: Sign hash
    uint8_t signature[256];
    size_t signature_len = sizeof(signature);
    status = SecKeyRawSign(privateKey,
                           kSecPaddingPKCS1SHA256,
                           digest, sizeof(digest),
                           signature, &signature_len);

    if (status != noErr) {
        if (error != NULL)
            *error = [SCCSR errorWithSecurityStatus:status];
        return nil;
    }
#else
    CFErrorRef cfError = NULL;
    SecTransformRef signer = SecSignTransformCreate(privateKey, &cfError);
    if (signer == NULL) {
        if (error != NULL)
            *error = CFBridgingRelease(cfError);
        else
            CFRelease(cfError);
        return nil;
    }
    if (!SecTransformSetAttribute(signer, kSecTransformInputAttributeName, (__bridge CFTypeRef _Nonnull)(certificationRequestInfo), &cfError)) {
        CFRelease(signer);
        if (error != NULL)
            *error = CFBridgingRelease(cfError);
        else
            CFRelease(cfError);
        return nil;
    }
    if (!SecTransformSetAttribute(signer, kSecDigestTypeAttribute, kSecDigestSHA2, &cfError)) {
        CFRelease(signer);
        if (error != NULL)
            *error = CFBridgingRelease(cfError);
        else
            CFRelease(cfError);
        return nil;
    }
    if (!SecTransformSetAttribute(signer, kSecPaddingKey, kSecPaddingPKCS1Key, &cfError)) {
        CFRelease(signer);
        if (error != NULL)
            *error = CFBridgingRelease(cfError);
        else
            CFRelease(cfError);
        return nil;
    }
    if (!SecTransformSetAttribute(signer, kSecDigestLengthAttribute, (__bridge CFTypeRef _Nonnull)(@( 256 )), &cfError)) {
        CFRelease(signer);
        if (error != NULL)
            *error = CFBridgingRelease(cfError);
        else
            CFRelease(cfError);
        return nil;
    }
    CFTypeRef signature = SecTransformExecute(signer, &cfError);
    CFRelease(signer);
    if (signature == NULL) {
        if (error != NULL)
            *error = CFBridgingRelease(cfError);
        else
            CFRelease(cfError);
        return nil;
    }
    assert(CFGetTypeID(signature) == CFDataGetTypeID());
#endif
	
	NSMutableData * certificationRequest = [[NSMutableData alloc] initWithCapacity:1024];
	[certificationRequest appendData:certificationRequestInfo];
	[certificationRequest appendBytes:SEQUENCE_OBJECT_sha256WithRSAEncryption length:sizeof(SEQUENCE_OBJECT_sha256WithRSAEncryption)];

	NSMutableData * signdata = [NSMutableData dataWithCapacity:257];
	uint8_t zero = 0;
	[signdata appendBytes:&zero length:1]; // Prepend zero
#if TARGET_OS_IPHONE
	[signdata appendBytes:signature length:signature_len];
#else
    [signdata appendData:(id)CFBridgingRelease(signature)];
#endif
	[SCCSR appendBITSTRING:signdata into:certificationRequest];

	[SCCSR enclose:certificationRequest by:SEQUENCE_tag]; // Enclose into SEQUENCE

	return certificationRequest;
}


-(NSMutableData *)buildCertificationRequestInfo:(NSData *)publicKeyBits
{
	NSMutableData * certificationRequestInfo = [[NSMutableData alloc] initWithCapacity:512];
	
	// Add version
	uint8_t version[3] = {0x02, 0x01, 0x00}; // ASN.1 Representation of integer with value 1
	[certificationRequestInfo appendBytes:version length:sizeof(version)];
	
	
	// Add subject
    if (subjectDER == nil) {
        NSMutableData * subject = [[NSMutableData alloc] initWithCapacity:256];
        if (countryName != nil) [SCCSR appendSubjectItem:OBJECT_countryName value:countryName into:subject];
        if (organizationName != nil) [SCCSR appendSubjectItem:OBJECT_organizationName value:organizationName into:subject];
        if (organizationalUnitName != nil) [SCCSR appendSubjectItem:OBJECT_organizationalUnitName value:organizationalUnitName into:subject];
        if (commonName != nil) [SCCSR appendSubjectItem:OBJECT_commonName value:commonName into:subject];
        [SCCSR enclose:subject by:SEQUENCE_tag]; // Enclose into SEQUENCE

        subjectDER = [NSData dataWithData:subject];
    }
	
	[certificationRequestInfo appendData:subjectDER];
	
	
	//Add public key info
	NSData * publicKeyInfo = [SCCSR buildPublicKeyInfo:publicKeyBits];
	[certificationRequestInfo appendData:publicKeyInfo];
	
	// Add attributes
	uint8_t attributes[2] = {0xA0, 0x00};
	[certificationRequestInfo appendBytes:attributes length:sizeof(attributes)];

	
	[SCCSR enclose:certificationRequestInfo by:SEQUENCE_tag]; // Enclose into SEQUENCE
	
	return certificationRequestInfo;
}

/// Utility class methods ...
+(NSData *)buildPublicKeyInfo:(NSData *)publicKeyBits
{
	NSMutableData * publicKeyInfo = [[NSMutableData alloc] initWithCapacity:390];

	[publicKeyInfo appendBytes:OBJECT_rsaEncryptionNULL length:sizeof(OBJECT_rsaEncryptionNULL)];
	[SCCSR enclose:publicKeyInfo by:SEQUENCE_tag]; // Enclose into SEQUENCE
	
	NSMutableData * publicKeyASN = [[NSMutableData alloc] initWithCapacity:260];
	
	NSData * mod = [SCCSR getPublicKeyMod:publicKeyBits];
	char Integer = 0x02; // Integer
	[publicKeyASN appendBytes:&Integer length:1];
	[SCCSR appendDERLength:[mod length] into:publicKeyASN];
	[publicKeyASN appendData:mod];

	NSData * exp = [SCCSR getPublicKeyExp:publicKeyBits];
	[publicKeyASN appendBytes:&Integer length:1];
	[SCCSR appendDERLength:[exp length] into:publicKeyASN];
	[publicKeyASN appendData:exp];

	[SCCSR enclose:publicKeyASN by:SEQUENCE_tag]; // Enclose into ??
	[SCCSR prependByte:0x00 into:publicKeyASN]; // Prepend 0 (?)
	
	[SCCSR appendBITSTRING:publicKeyASN into:publicKeyInfo];
	
	[SCCSR enclose:publicKeyInfo by:SEQUENCE_tag]; // Enclose into SEQUENCE
	
	return publicKeyInfo;
}

+(void)appendSubjectItem:(const uint8_t[5])what value:(NSString *)value into:(NSMutableData *)into
{
	NSMutableData * subjectItem = [[NSMutableData alloc] initWithCapacity:128];
	[subjectItem appendBytes:what length:5];
	[SCCSR appendUTF8String:value into:subjectItem];
	[SCCSR enclose:subjectItem by:SEQUENCE_tag]; // Enclose into SEQUENCE
	[SCCSR enclose:subjectItem by:SET_tag]; // Enclose into SET
	
	[into appendData:subjectItem];
}

+(void)appendUTF8String:(NSString *)string into:(NSMutableData *)into
{
	char strtype = 0x0C; //UTF8STRING
	[into appendBytes:&strtype length:1];
	[SCCSR appendDERLength:[string lengthOfBytesUsingEncoding:NSUTF8StringEncoding] into:into];
	[into appendData:(id)[string dataUsingEncoding:NSUTF8StringEncoding]];
}

+(void)appendDERLength:(size_t)length into:(NSMutableData *)into
{
	assert(length < 0x8000);
	
	if (length < 128)
	{
		uint8_t d = length;
		[into appendBytes:&d length:1];
	}
	else if (length < 0x100)
	{
		uint8_t d[2] = {0x81, length & 0xFF};
		[into appendBytes:&d length:2];
	}
	else if (length < 0x8000)
	{
		uint8_t d[3] = {0x82, (length & 0xFF00) >> 8, length & 0xFF};
		[into appendBytes:&d length:3];
	}
}

+(void)appendBITSTRING:(NSData *)data into:(NSMutableData *)into
{
	char strtype = 0x03; //BIT STRING
	[into appendBytes:&strtype length:1];
	[SCCSR appendDERLength:[data length] into:into];
	[into appendData:data];
}


+(void)enclose:(NSMutableData *)data by:(uint8_t)by
{
	NSMutableData* newdata = [[NSMutableData alloc]initWithCapacity:[data length]+4];
	
	[newdata appendBytes:&by length:1];
	[SCCSR appendDERLength:[data length] into:newdata];
	[newdata appendData:data];
	
	[data setData:newdata];
}

+(void)prependByte:(uint8_t)byte into:(NSMutableData *)into
{
	NSMutableData* newdata = [[NSMutableData alloc]initWithCapacity:[into length]+1];
	
	[newdata appendBytes:&byte length:1];
	[newdata appendData:into];
	
	[into setData:newdata];
}

///

// From http://stackoverflow.com/questions/3840005/how-to-find-out-the-modulus-and-exponent-of-rsa-public-key-on-iphone-objective-c

+ (NSData *)getPublicKeyExp:(NSData *)publicKeyBits
{
	int iterator = 0;
	
	iterator++; // TYPE - bit stream - mod + exp
	[SCCSR derEncodingGetSizeFrom:publicKeyBits at:&iterator]; // Total size
	
	iterator++; // TYPE - bit stream mod
	int mod_size = [SCCSR derEncodingGetSizeFrom:publicKeyBits at:&iterator];
	iterator += mod_size;
	
	iterator++; // TYPE - bit stream exp
	int exp_size = [SCCSR derEncodingGetSizeFrom:publicKeyBits at:&iterator];
	
	return [publicKeyBits subdataWithRange:NSMakeRange(iterator, exp_size)];
}

+(NSData *)getPublicKeyMod:(NSData *)publicKeyBits
{
	int iterator = 0;
	
	iterator++; // TYPE - bit stream - mod + exp
	[SCCSR derEncodingGetSizeFrom:publicKeyBits at:&iterator]; // Total size
	
	iterator++; // TYPE - bit stream mod
	int mod_size = [SCCSR derEncodingGetSizeFrom:publicKeyBits at:&iterator];
	
	return [publicKeyBits subdataWithRange:NSMakeRange(iterator, mod_size)];
}

+(int)derEncodingGetSizeFrom:(NSData*)buf at:(int*)iterator
{
	const uint8_t* data = [buf bytes];
	int itr = *iterator;
	int num_bytes = 1;
	int ret = 0;
	
	if (data[itr] > 0x80) {
		num_bytes = data[itr] - 0x80;
		itr++;
	}
	
	for (int i = 0 ; i < num_bytes; i++) ret = (ret * 0x100) + data[itr + i];
	
	*iterator = itr + num_bytes;
	return ret;
}

@end

