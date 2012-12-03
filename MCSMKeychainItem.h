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

@property (readonly, copy) NSString *username;
@property (readonly, copy) NSString *password;

- (BOOL)removeFromKeychain;

@end 


@interface MCSMGenericKeychainItem : MCSMKeychainItem

@property (readonly, copy) NSString *service;

#if TARGET_OS_IPHONE

+ (NSArray *)genericKeychainItemsForService:(NSString *)service;

#endif

+ (MCSMGenericKeychainItem *)genericKeychainItemForService:(NSString *)service
                                                  username:(NSString *)username;

+ (MCSMGenericKeychainItem *)genericKeychainItemWithService:(NSString *)service
                                                   username:(NSString *)username
                                                   password:(NSString *)password;
@end


extern NSString *const MCSMApplicationUUIDKeychainItemService;

@interface MCSMApplicationUUIDKeychainItem : MCSMGenericKeychainItem

@property (readonly, copy) NSString *UUID;

+ (MCSMApplicationUUIDKeychainItem *)generateApplicationUUIDKeychainItem;
+ (MCSMApplicationUUIDKeychainItem *)applicationUUIDKeychainItem;

+ (NSString *)applicationUUID;

@end