//
//  MCSMKeychainItem.m
//  MCSMFoundation
//
//  Created by Spencer MacDonald on 12/10/2011.
//  Copyright 2012 Square Bracket Software. All rights reserved.
//

#import "MCSMKeychainItem.h"

@interface MCSMKeychainItem ()

#if TARGET_OS_MAC && !TARGET_IPHONE_SIMULATOR && !TARGET_OS_IPHONE	

- (id)_initWithKeychainItemRef:(SecKeychainItemRef)keychainItemRef
                      username:(NSString *)username
                      password:(NSString *)password;

#elif TARGET_OS_IPHONE

- (id)_initWithUsername:(NSString *)username
               password:(NSString *)password;
#endif

@end

@implementation MCSMKeychainItem{
@private
	NSString *username_;
	NSString *password_;
    
#if TARGET_OS_MAC && !TARGET_IPHONE_SIMULATOR && !TARGET_OS_IPHONE	
@protected
	SecKeychainItemRef keychainItemRef_;
#endif
}


@synthesize username = username_;
@synthesize password = password_;


#pragma mark -

#if TARGET_OS_MAC && !TARGET_IPHONE_SIMULATOR && !TARGET_OS_IPHONE	

- (id)_initWithKeychainItemRef:(SecKeychainItemRef)keychainItemRef
                      username:(NSString *)username
                      password:(NSString *)password{
    
	if ((self = [super init])){
		keychainItemRef_ = keychainItemRef;
		username_ = [username copy];
		password_ = [password copy];
	}
	return self;
}

#elif TARGET_OS_IPHONE

- (id)_initWithUsername:(NSString *)username
               password:(NSString *)password{
	
    if((self = [super init])){
		username_ = [username copy];
		password_ = [password copy];
		
	}
	return self;
}

#endif


#if TARGET_OS_MAC && !TARGET_IPHONE_SIMULATOR && !TARGET_OS_IPHONE

+ (void)lockKeychain{
	SecKeychainLock(NULL);
}

+ (void)unlockKeychain{
	SecKeychainUnlock(NULL, 0, NULL, NO);
}

#endif



- (void)dealloc{
	[username_ release], username_ = nil;
	[password_ release], password_ = nil;
	
#if TARGET_OS_MAC && !TARGET_IPHONE_SIMULATOR && !TARGET_OS_IPHONE

	if (keychainItemRef_)
    {
		CFRelease(keychainItemRef_);
    }
#endif
	
	[super dealloc];
}


- (NSString *)description{
    return [NSString stringWithFormat:@"%@ username:%@",NSStringFromClass([self class]),self.username];
}

#pragma mark -
#pragma mark Actions

#if TARGET_OS_MAC && !TARGET_IPHONE_SIMULATOR && !TARGET_OS_IPHONE

- (BOOL)removeFromKeychain{
    
    BOOL removed = NO;    	
	if (keychainItemRef_)
	{
		OSStatus resultStatus = SecKeychainItemDelete(keychainItemRef_);
        
		if (resultStatus == noErr)
		{
            removed = YES;
			CFRelease(keychainItemRef_);
			keychainItemRef_ = nil;
		}
	}
	
    return removed;
}

#elif TARGET_OS_IPHONE

- (BOOL)removeFromKeychain{
    
    BOOL removed = NO;
    
    NSDictionary *query = [NSDictionary dictionaryWithObjectsAndKeys:[self username], kSecAttrAccount, kSecClassGenericPassword, kSecClass, nil];
    OSStatus resultStatus = SecItemDelete((CFDictionaryRef)query);
    
    if(resultStatus != noErr)
    {
#if DEBUG
        NSLog(@"Error (%@) - %ld query %@",NSStringFromSelector(_cmd),resultStatus,query);
#endif
    }else{
        removed = YES;
    }
    
    return removed;
}

#endif

@end


@interface MCSMGenericKeychainItem ()


#if TARGET_OS_MAC && !TARGET_IPHONE_SIMULATOR && !TARGET_OS_IPHONE


- (id)_initWithKeychainItemRef:(SecKeychainItemRef)item
                       service:(NSString *)service
                      username:(NSString *)username
                      password:(NSString *)password;

#elif TARGET_OS_IPHONE

- (id)_initWithService:(NSString *)service
              username:(NSString *)username
              password:(NSString *)password;
#endif


#if TARGET_OS_MAC && !TARGET_IPHONE_SIMULATOR && !TARGET_OS_IPHONE	


+ (id)_genericKeychainItemWithKeychainItemRef:(SecKeychainItemRef)coreKeychainItem 
                                      service:(NSString *)service
                                     username:(NSString *)username
                                     password:(NSString *)password;

#elif TARGET_OS_IPHONE

+ (id)_genericKeychainItemWithService:(NSString *)service
                             username:(NSString *)username
                             password:(NSString *)password;

#endif

@end


@implementation MCSMGenericKeychainItem{
@private
	NSString *service_;
}

@synthesize service = service_;


#if TARGET_OS_MAC  && !TARGET_IPHONE_SIMULATOR && !TARGET_OS_IPHONE


- (id)_initWithKeychainItemRef:(SecKeychainItemRef)item
                       service:(NSString *)service
                      username:(NSString *)username
                      password:(NSString *)password{
    
	if ((self = [super _initWithKeychainItemRef:item username:username password:password])){
		service_ = [service copy];
	}
	return self;
}

#elif TARGET_OS_IPHONE


- (id)_initWithService:(NSString *)service
              username:(NSString *)username
              password:(NSString *)password{
    
	if ((self = [super _initWithUsername:username password:password])){
		service_ = [service copy];
	}
	return self;
}

#endif


#if TARGET_OS_MAC && !TARGET_IPHONE_SIMULATOR && !TARGET_OS_IPHONE


+ (id)_genericKeychainItemWithKeychainItemRef:(SecKeychainItemRef)coreKeychainItem 
                                      service:(NSString *)service
                                     username:(NSString *)username
                                     password:(NSString *)password{
    
	return [[[self alloc] _initWithKeychainItemRef:coreKeychainItem
                                           service:service
                                          username:username
                                          password:password] autorelease];
}

#elif TARGET_OS_IPHONE

+ (id)_genericKeychainItemWithService:(NSString *)service
                             username:(NSString *)username
                             password:(NSString *)password{
    
	return [[[self alloc] _initWithService:service
                                  username:username
                                  password:password] autorelease];
}

#endif

- (void)dealloc{
	[service_ release], service_ = nil;

	[super dealloc];
}

- (NSString *)description{
    return [NSString stringWithFormat:@"%@ service:%@ username:%@",NSStringFromClass([self class]),self.service,self.username];
}



#if TARGET_OS_MAC && !TARGET_IPHONE_SIMULATOR && !TARGET_OS_IPHONE

- (BOOL)removeFromKeychain{
    
    BOOL removed = NO;
    
	if (keychainItemRef_)
	{
		OSStatus resultStatus = SecKeychainItemDelete(keychainItemRef_);
        
		if (resultStatus == noErr)
		{
            removed = YES;
			CFRelease(keychainItemRef_);
			keychainItemRef_ = nil;
		}
	}
	
    
    return removed;
}


#elif TARGET_OS_IPHONE



- (BOOL)removeFromKeychain{
    
    BOOL removed = NO;
    
	NSMutableDictionary *query = [NSMutableDictionary dictionary];
    [query setObject:kSecClassGenericPassword forKey:kSecClass];
    [query setObject:[self service] forKey:kSecAttrService];
    [query setObject:[self username] forKey:kSecAttrAccount];
    
	OSStatus resultStatus = SecItemDelete((CFDictionaryRef)query);
    
	if (resultStatus != noErr)
	{
#if DEBUG
        NSLog(@"Error (%@) - %ld query %@",NSStringFromSelector(_cmd),resultStatus,query);
#endif
	}else{
        removed = YES;
    }
    
    return removed;
}

#endif


#pragma mark -


#if TARGET_OS_IPHONE

+ (NSArray *)genericKeychainItemsForService:(NSString *)service{
    
    NSMutableArray *genericKeychainItems = nil;
    
    NSMutableDictionary *query = [NSMutableDictionary dictionary];
    [query setObject:service forKey:kSecAttrService];
    [query setObject:kSecClassGenericPassword forKey:kSecClass];
    [query setObject:(id)kSecMatchLimitAll forKey:(id)kSecMatchLimit];
    [query setObject:(id)kCFBooleanTrue forKey:(id)kSecReturnAttributes];
    [query setObject:(id)kCFBooleanTrue forKey:(id)kSecReturnData];
    
    NSMutableDictionary *queryResults = nil;
    OSStatus returnStatus = SecItemCopyMatching((CFDictionaryRef)query, (CFTypeRef *)&queryResults);
            
    if (returnStatus != noErr) 
    {
#if DEBUG
        NSLog(@"Error (%@) - %ld query %@",NSStringFromSelector(_cmd),returnStatus,query);
#endif
    }else{
        
        genericKeychainItems = [NSMutableArray array];
        
        CFArrayRef secItems = (CFArrayRef)queryResults;
        
        unsigned numberOfSecItems = CFArrayGetCount(secItems);
                
        for (int i = 0; i < numberOfSecItems; i++){
            
            NSDictionary *secItem = CFArrayGetValueAtIndex(secItems,i);
        
            NSData *passwordData = [secItem objectForKey:(id)kSecValueData];
            
            NSString *password = [[NSString alloc] initWithBytes:[passwordData bytes] 
                                                          length:[passwordData length] 
                                                        encoding:NSUTF8StringEncoding];
            
            MCSMGenericKeychainItem *genericKeychainItem = nil;
            genericKeychainItem = [self _genericKeychainItemWithService:service
                                                               username:[secItem objectForKey:(id)kSecAttrAccount]
                                                               password:password];
            
            [password release];
            
            if(genericKeychainItem)
            {
                [genericKeychainItems addObject:genericKeychainItem];
            }
        }
        
        
    }
    
    
    return genericKeychainItems;
}

#endif


#if TARGET_OS_MAC && !TARGET_IPHONE_SIMULATOR && !TARGET_OS_IPHONE

+ (MCSMGenericKeychainItem *)genericKeychainItemForService:(NSString *)service 
                                                  username:(NSString *)username
{
	if (!service || !username)
    {
		return nil;
    }
	
	const char *serviceCString = [service UTF8String];
	const char *usernameCString = [username UTF8String];
	
	UInt32 passwordLength = 0;
	char *password = nil;
	
	SecKeychainItemRef item = nil;
	OSStatus returnStatus = SecKeychainFindGenericPassword(NULL, (UInt32)strlen(serviceCString), serviceCString, (UInt32)strlen(usernameCString), usernameCString, &passwordLength, (void **)&password, &item);
	if (returnStatus != noErr || !item)
	{
#if DEBUG
			NSLog(@"Error (%@) - %s", NSStringFromSelector(_cmd), GetMacOSStatusErrorString(returnStatus));
#endif
		return nil;
	}
	NSString *passwordString = [[[NSString alloc] initWithData:[NSData dataWithBytes:password length:passwordLength] encoding:NSUTF8StringEncoding] autorelease];
	SecKeychainItemFreeContent(NULL, password);
	
	return [self _genericKeychainItemWithKeychainItemRef:item 
                                                 service:service 
                                                username:username 
                                                password:passwordString];
}


#elif TARGET_OS_IPHONE


+ (MCSMGenericKeychainItem *)genericKeychainItemForService:(NSString *)service 
                                                  username:(NSString *)username{

    NSMutableDictionary *query = [NSMutableDictionary dictionary];
    [query setObject:service forKey:kSecAttrService];
    if(username)
    {
        [query setObject:username forKey:kSecAttrAccount];
    }
    [query setObject:kSecClassGenericPassword forKey:kSecClass];
    [query setObject:(id)kSecMatchLimitOne forKey:(id)kSecMatchLimit];
    [query setObject:(id)kCFBooleanTrue forKey:(id)kSecReturnAttributes];
    [query setObject:(id)kCFBooleanTrue forKey:(id)kSecReturnData];

    NSMutableDictionary *results = nil;
    OSStatus returnStatus = SecItemCopyMatching((CFDictionaryRef)query, (CFTypeRef *)&results);
    
    MCSMGenericKeychainItem *genericKeychainItem = nil;
    if (returnStatus != noErr) 
    {
#if DEBUG
     NSLog(@"Error (%@) - %ld query %@",NSStringFromSelector(_cmd),returnStatus,query);
#endif
    }else{

        NSData *passwordData = [results objectForKey:(id)kSecValueData];

        NSString *password = [[NSString alloc] initWithBytes:[passwordData bytes] 
                                                      length:[passwordData length] 
                                                    encoding:NSUTF8StringEncoding];
        
        genericKeychainItem = [self _genericKeychainItemWithService:service
                                                           username:[results objectForKey:(id)kSecAttrAccount]
                                                           password:password];
        [password release];
            
   
    }

    
    
    return genericKeychainItem;
}

#endif


#if TARGET_OS_MAC && !TARGET_IPHONE_SIMULATOR && !TARGET_OS_IPHONE

+ (MCSMGenericKeychainItem *)genericKeychainItemWithService:(NSString *)service
                                                   username:(NSString *)username
                                                   password:(NSString *)password{
	if (!service || !username || !password)
    {
		return nil;
    }
	
	const char *serviceCString = [service UTF8String];
	const char *usernameCString = [username UTF8String];
	const char *passwordCString = [password UTF8String];
	
	SecKeychainItemRef item = nil;
	OSStatus returnStatus = SecKeychainAddGenericPassword(NULL, (UInt32)strlen(serviceCString), serviceCString, (UInt32)strlen(usernameCString), usernameCString, (UInt32)strlen(passwordCString), (void *)passwordCString, &item);
	
	if (returnStatus != noErr || !item)
	{
#if DEBUG
        NSLog(@"Error (%@) - %s", NSStringFromSelector(_cmd), GetMacOSStatusErrorString(returnStatus));
#endif
		return nil;
	}
	return [MCSMGenericKeychainItem _genericKeychainItemWithKeychainItemRef:item 
                                                                    service:service 
                                                                   username:username 
                                                                   password:password];
}

#elif TARGET_OS_IPHONE

+ (MCSMGenericKeychainItem *)genericKeychainItemWithService:(NSString *)service
                                                   username:(NSString *)username
                                                   password:(NSString *)password{
    if (!username || !service || !password) 
    { 
        return nil;
    }
    
    NSMutableDictionary *query = [NSMutableDictionary dictionary];
    [query setObject:service forKey:kSecAttrService];
    [query setObject:username forKey:kSecAttrAccount];
    [query setObject:kSecClassGenericPassword forKey:kSecClass];
    [query setObject:[password dataUsingEncoding:NSUTF8StringEncoding] forKey:kSecValueData];
    
    OSStatus returnStatus = SecItemAdd((CFDictionaryRef)query, NULL);
    
    MCSMGenericKeychainItem *genericKeychainItem = nil;
    if (returnStatus) 
    { 
#if DEBUG
    NSLog(@"Error (%@) - %ld query %@",NSStringFromSelector(_cmd),returnStatus,query);
#endif
     
    }else{
        genericKeychainItem = [self genericKeychainItemForService:service 
                                                         username:username];
    }
    return genericKeychainItem;
}

#endif


@end

NSString *const MCSMApplicationUUIDKeychainItemService = @"com.squarebracketsoftware.opensource.keychain.uuid.application";

@implementation MCSMApplicationUUIDKeychainItem

+ (MCSMApplicationUUIDKeychainItem *)generateApplicationUUIDKeychainItem{
    
    CFUUIDRef UUIDRef = CFUUIDCreate(kCFAllocatorDefault);
    CFStringRef UUIDStringRef = CFUUIDCreateString(kCFAllocatorDefault, UUIDRef);
    NSString *UUIDString = [NSString stringWithString:(NSString *)UUIDStringRef];
    CFRelease(UUIDStringRef);
    CFRelease(UUIDRef);
    
    return (MCSMApplicationUUIDKeychainItem *)[self genericKeychainItemWithService:MCSMApplicationUUIDKeychainItemService
                                                               username:[[[NSBundle mainBundle] infoDictionary] objectForKey:@"CFBundleIdentifier"] 
                                                               password:UUIDString];
    
}
+ (MCSMApplicationUUIDKeychainItem *)applicationUUIDKeychainItem{
    
    return  (MCSMApplicationUUIDKeychainItem *)[self genericKeychainItemForService:MCSMApplicationUUIDKeychainItemService
                                                               username:[[[NSBundle mainBundle] infoDictionary] objectForKey:@"CFBundleIdentifier"]]; 

}

+ (NSString *)applicationUUID{
    MCSMApplicationUUIDKeychainItem *applicationUDIDKeychainItem = [self applicationUUIDKeychainItem];
    
    if(!applicationUDIDKeychainItem)
    {
        applicationUDIDKeychainItem = [self generateApplicationUUIDKeychainItem];
    }
    
    return applicationUDIDKeychainItem.UUID;
}


- (NSString *)description{
    return [NSString stringWithFormat:@"%@ service:%@ username:%@ uuid:%@",NSStringFromClass([self class]),self.service,self.username,self.UUID];
}


- (NSString *)UUID{
    return self.password;
}

@end
