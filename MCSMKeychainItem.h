//
//  MCSMKeychainItem.h
//  MCSMSecurity
//
//  Created by Spencer MacDonald on 12/10/2011.
//  Copyright 2012 Square Bracket Software. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <Security/Security.h>

@interface MCSMKeychainItem : NSObject

#if TARGET_OS_MAC && !TARGET_IPHONE_SIMULATOR && !TARGET_OS_IPHONE

+ (void)lockKeychain;
+ (void)unlockKeychain;

#endif

@property (readonly, copy) NSString *account;
@property (readonly, retain) NSDictionary *attributes;
@property (readonly, copy) NSString *password;

// Keyed Subscript Accessor for attributes
- (id)objectForKeyedSubscript:(id <NSCopying>)key;

- (BOOL)removeFromKeychain;

@end

@interface MCSMGenericKeychainItem : MCSMKeychainItem

@property (readonly, copy) NSString *service;

+ (NSArray *)genericKeychainItemsForService:(NSString *)service
                                 attributes:(NSDictionary *)attributes;

+ (instancetype)genericKeychainItemForService:(NSString *)service
                                      account:(NSString *)account
                                   attributes:(NSDictionary *)attributes;

+ (instancetype)genericKeychainItemWithService:(NSString *)service
                                       account:(NSString *)account
                                    attributes:(NSDictionary *)attributes
                                      password:(NSString *)password;
@end

@interface MCSMInternetKeychainItem : MCSMKeychainItem

@property (readonly, copy) NSString *server;
@property (readonly, copy) NSString *securityDomain;
@property (readonly, copy) NSString *path;
@property (readonly, assign) UInt16 port;
@property (readonly, assign) CFTypeRef protocol;
@property (readonly, assign) CFTypeRef authenticationType;

+ (NSArray *)internetKeychainItemsForServer:(NSString *)server
                             securityDomain:(NSString *)securityDomain
                                       path:(NSString *)path
                                       port:(UInt16)port
                                   protocol:(CFTypeRef)protocol
                         authenticationType:(CFTypeRef)authenticationType
                                 attributes:(NSDictionary *)attributes;

+ (instancetype)internetKeychainItemForServer:(NSString *)server
                               securityDomain:(NSString *)securityDomain
                                      account:(NSString *)account
                                         path:(NSString *)path
                                         port:(UInt16)port
                                     protocol:(CFTypeRef)protocol
                           authenticationType:(CFTypeRef)authenticationType
                                   attributes:(NSDictionary *)attributes;

+ (instancetype)internetKeychainItemWithServer:(NSString *)server
                                securityDomain:(NSString *)securityDomain
                                       account:(NSString *)account
                                          path:(NSString *)path
                                          port:(UInt16)port
                                      protocol:(CFTypeRef)protocol
                            authenticationType:(CFTypeRef)authenticationType
                                    attributes:(NSDictionary *)attributes
                                      password:(NSString *)password;
@end

extern NSString *const MCSMApplicationUUIDKeychainItemService;

@interface MCSMApplicationUUIDKeychainItem : MCSMGenericKeychainItem

@property (readonly, copy) NSString *UUID;

+ (MCSMApplicationUUIDKeychainItem *)generateApplicationUUIDKeychainItem;
+ (MCSMApplicationUUIDKeychainItem *)applicationUUIDKeychainItem;

+ (NSString *)applicationUUID;

@end