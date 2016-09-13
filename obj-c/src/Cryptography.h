//
//  Cryptography.h
//
//  Created by aelchim.
//
//

#import <Foundation/Foundation.h>

@interface Cryptography : NSObject {
    
}

+ (NSData *)encryptedDataForData:(NSData *)data
                        password:(NSString *)password
                              iv:(NSData **)iv
                            salt:(NSData **)salt
                           error:(NSError **)error;
+ (NSData *)randomDataOfLength:(size_t)length;
+ (NSData *)AESKeyForPassword:(NSString *)password
                         salt:(NSData *)salt;
+ (NSData *)encryptedDataForRequest:(NSData *)data
                               password:(NSString *)password
                                     iv:(NSData **)iv
                                   salt:(NSData **)salt
                                  error:(NSError **)error;
+ (NSString *)base64String:(NSData *)encryptedData;
+ (NSData *)decryptedDataForRequest:(NSData *)data
                           password:(NSString *)password
                                 iv:(NSData **)iv
                               salt:(NSData **)salt
                              error:(NSError **)error;
@end
