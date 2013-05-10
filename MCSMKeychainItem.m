//
//  MCSMKeychainItem.m
//  MCSMSecurity
//
//  Created by Spencer MacDonald on 12/10/2011.
//  Copyright 2012 Square Bracket Software. All rights reserved.
//

#import "MCSMKeychainItem.h"

@interface MCSMKeychainItem ()


- (id)_initWithAccount:(NSString *)account
              password:(NSString *)password;
@end

@implementation MCSMKeychainItem{
@private
	NSString *account_;
	NSString *password_;
    
}


@synthesize account = account_;
@synthesize password = password_;


#pragma mark -

- (id)_initWithAccount:(NSString *)account
              password:(NSString *)password{
	
    if((self = [super init])){
		account_ = [account copy];
		password_ = [password copy];
		
	}
	return self;
}


#if TARGET_OS_MAC && !TARGET_IPHONE_SIMULATOR && !TARGET_OS_IPHONE

+ (void)lockKeychain{
	SecKeychainLock(NULL);
}

+ (void)unlockKeychain{
	SecKeychainUnlock(NULL, 0, NULL, NO);
}

#endif



- (void)dealloc{
	[account_ release], account_ = nil;
	[password_ release], password_ = nil;
	
	
	[super dealloc];
}


- (NSString *)description{
    return [NSString stringWithFormat:@"%@ account:%@",NSStringFromClass([self class]),self.account];
}

#pragma mark -
#pragma mark Actions


- (BOOL)removeFromKeychain{
    
    BOOL removed = NO;
    
    NSDictionary *query = [NSDictionary dictionaryWithObjectsAndKeys:[self account], kSecAttrAccount, kSecClassGenericPassword, kSecClass, nil];
    OSStatus resultStatus = SecItemDelete((CFDictionaryRef)query);
    
    if(resultStatus != noErr)
    {
#if DEBUG
        NSLog(@"Error (%@) - %@ query %@",NSStringFromSelector(_cmd),[NSError errorWithDomain:NSOSStatusErrorDomain code:resultStatus userInfo:nil],query);
#endif
    }else{
        removed = YES;
    }
    
    return removed;
}

@end


@interface MCSMGenericKeychainItem ()



- (id)_initWithService:(NSString *)service
               account:(NSString *)account
              password:(NSString *)password;


+ (id)_genericKeychainItemWithService:(NSString *)service
                             account:(NSString *)account
                             password:(NSString *)password;

@end


@implementation MCSMGenericKeychainItem{
@private
	NSString *service_;
}

@synthesize service = service_;



- (id)_initWithService:(NSString *)service
               account:(NSString *)account
              password:(NSString *)password{
    
	if ((self = [super _initWithAccount:account password:password])){
		service_ = [service copy];
	}
	return self;
}


+ (id)_genericKeychainItemWithService:(NSString *)service
                             account:(NSString *)account
                             password:(NSString *)password{
    
	return [[[self alloc] _initWithService:service
                                  account:account
                                  password:password] autorelease];
}


- (void)dealloc{
	[service_ release], service_ = nil;
    
	[super dealloc];
}

- (NSString *)description{
    return [NSString stringWithFormat:@"%@ service:%@ account:%@",NSStringFromClass([self class]),self.service,self.account];
}


- (BOOL)removeFromKeychain{
    
    BOOL removed = NO;
    
	NSMutableDictionary *query = [NSMutableDictionary dictionary];
    
    [query setObject:kSecClassGenericPassword forKey:kSecClass];
    
    if([[self service] length])
    {
        [query setObject:[self service] forKey:kSecAttrService];
    }
    
    if([[self account] length])
    {
        [query setObject:[self account] forKey:kSecAttrAccount];
    }
    
	OSStatus resultStatus = SecItemDelete((CFDictionaryRef)query);
    
	if (resultStatus != noErr)
	{
#if DEBUG
        NSLog(@"Error (%@) - %@ query %@",NSStringFromSelector(_cmd),[NSError errorWithDomain:NSOSStatusErrorDomain code:resultStatus userInfo:nil],query);
#endif
	}else{
        removed = YES;
    }
    
    return removed;
}

#pragma mark -

+ (NSArray *)genericKeychainItemsForService:(NSString *)service{
    
    NSMutableArray *genericKeychainItems = nil;
    
    NSMutableDictionary *query = [NSMutableDictionary dictionary];
    
    [query setObject:kSecClassGenericPassword forKey:kSecClass];
    
    if([service length])
    {
        [query setObject:service forKey:kSecAttrService];
    }
    
    [query setObject:kSecMatchLimitAll forKey:kSecMatchLimit];
    
    [query setObject:@YES forKey:kSecReturnAttributes];
    
    NSMutableDictionary *queryResults = nil;
    OSStatus returnStatus = SecItemCopyMatching((CFDictionaryRef)query, (CFTypeRef *)&queryResults);
    
    if (returnStatus != noErr)
    {
#if DEBUG
        NSLog(@"Error (%@) - %@ query %@",NSStringFromSelector(_cmd),[NSError errorWithDomain:NSOSStatusErrorDomain code:returnStatus userInfo:nil],query);
#endif
    }else{
        
        genericKeychainItems = [NSMutableArray array];
        
        CFArrayRef secItems = (CFArrayRef)queryResults;
        
        NSUInteger numberOfSecItems = CFArrayGetCount(secItems);
        
        for (NSUInteger i = 0; i < numberOfSecItems; i++){
            
            NSDictionary *secItem = CFArrayGetValueAtIndex(secItems,i);
            
            MCSMGenericKeychainItem *genericKeychainItem = nil;
            genericKeychainItem = [self genericKeychainItemForService:service
                                                              account:[secItem objectForKey:kSecAttrAccount]];
                        
            if(genericKeychainItem)
            {
                [genericKeychainItems addObject:genericKeychainItem];
            }
        }
        
        
    }
    
    
    return genericKeychainItems;
}


+ (MCSMGenericKeychainItem *)genericKeychainItemForService:(NSString *)service
                                                   account:(NSString *)account{
    
    NSMutableDictionary *query = [NSMutableDictionary dictionary];
    
    [query setObject:kSecClassGenericPassword forKey:kSecClass];

    if([service length])
    {
        [query setObject:service forKey:kSecAttrService];
    }
    
    if([account length])
    {
        [query setObject:account forKey:kSecAttrAccount];
    }
    
    [query setObject:kSecMatchLimitOne forKey:kSecMatchLimit];
    [query setObject:@YES forKey:kSecReturnAttributes];
    [query setObject:@YES forKey:kSecReturnData];
    
    NSMutableDictionary *results = nil;
    OSStatus returnStatus = SecItemCopyMatching((CFDictionaryRef)query, (CFTypeRef *)&results);
    
    MCSMGenericKeychainItem *genericKeychainItem = nil;
    if (returnStatus != noErr)
    {
#if DEBUG
        NSLog(@"Error (%@) - %@ query %@",NSStringFromSelector(_cmd),[NSError errorWithDomain:NSOSStatusErrorDomain code:returnStatus userInfo:nil],query);
#endif
    }else{
        
        NSData *passwordData = [results objectForKey:kSecValueData];
        
        NSString *password = [[NSString alloc] initWithBytes:[passwordData bytes]
                                                      length:[passwordData length]
                                                    encoding:NSUTF8StringEncoding];
        
        genericKeychainItem = [self _genericKeychainItemWithService:service
                                                            account:[results objectForKey:kSecAttrAccount]
                                                           password:password];
        [password release];
        
        
    }
    
    [results release];
    
    return genericKeychainItem;
}

+ (MCSMGenericKeychainItem *)genericKeychainItemWithService:(NSString *)service
                                                    account:(NSString *)account
                                                   password:(NSString *)password{
    
    NSMutableDictionary *query = [NSMutableDictionary dictionary];
    
    [query setObject:kSecClassGenericPassword forKey:kSecClass];
    
    [query setObject:service forKey:kSecAttrService];
    [query setObject:account forKey:kSecAttrAccount];
    [query setObject:[password dataUsingEncoding:NSUTF8StringEncoding] forKey:kSecValueData];
    
    OSStatus returnStatus = SecItemAdd((CFDictionaryRef)query, NULL);
    
    MCSMGenericKeychainItem *genericKeychainItem = nil;
    
    if (returnStatus)
    {
#if DEBUG
        NSLog(@"Error (%@) - %@ query %@",NSStringFromSelector(_cmd),[NSError errorWithDomain:NSOSStatusErrorDomain code:returnStatus userInfo:nil],query);
#endif
        
    }else{
        genericKeychainItem = [self genericKeychainItemForService:service
                                                         account:account];
    }
    return genericKeychainItem;
}


@end

@implementation MCSMInternetKeychainItem{
@private
	NSString *server_;
    NSString *securityDomain_;
    NSString *path_;
    UInt16 port_;
    CFTypeRef protocol_;
    CFTypeRef authenticationType_;
}

@synthesize server = server_;
@synthesize securityDomain = securityDomain_;
@synthesize path = path_;
@synthesize port = port_;
@synthesize protocol = protocol_;
@synthesize authenticationType = authenticationType_;


- (id)_initWithServer:(NSString *)server
       securityDomain:(NSString *)securityDomain
              account:(NSString *)account
                 path:(NSString *)path
                 port:(UInt16)port
             protocol:(CFTypeRef)protocol
   authenticationType:(CFTypeRef)authenticationType
             password:(NSString *)password
{
    
	if ((self = [super _initWithAccount:account password:password])){
		server_ = [server copy];
        securityDomain_ = [securityDomain copy];
        path_ = [path copy];
        port_ = port;
        protocol_ = CFRetain(protocol);
        authenticationType_ = CFRetain(authenticationType);
	}
	return self;
}




+ (id)_internetKeychainItemWithServer:(NSString *)server
                       securityDomain:(NSString *)securityDomain
                              account:(NSString *)account
                                 path:(NSString *)path
                                 port:(UInt16)port
                             protocol:(CFTypeRef)protocol
                   authenticationType:(CFTypeRef)authenticationType
                             password:(NSString *)password
{
    
	return [[[self alloc] _initWithServer:server
                           securityDomain:securityDomain
                                  account:account
                                     path:path
                                     port:port
                                 protocol:protocol
                       authenticationType:authenticationType
                                 password:password] autorelease];
}

- (void)dealloc{
	[server_ release], server_ = nil;
    [securityDomain_ release], securityDomain_ = nil;
    [path_ release], path_ = nil;
    CFRelease(protocol_), protocol_ = NULL;
    CFRelease(authenticationType_), authenticationType_ = NULL;
    
	[super dealloc];
}

#if TARGET_OS_MAC && !TARGET_IPHONE_SIMULATOR && !TARGET_OS_IPHONE

- (NSString *)description{
    return [NSString stringWithFormat:@"%@ server:%@ securityDomain:%@ account:%@ path:%@ port:%i",NSStringFromClass([self class]),self.server,self.securityDomain, self.account,self.path,self.port];
}

#elif TARGET_OS_IPHONE

- (NSString *)description{
    return [NSString stringWithFormat:@"%@ server:%@ securityDomain:%@ account:%@ path:%@ port:%i",NSStringFromClass([self class]),self.server,self.securityDomain, self.account,self.path,self.port];
}

#endif


- (BOOL)removeFromKeychain{
    
    BOOL removed = NO;
    
	NSMutableDictionary *query = [NSMutableDictionary dictionary];
    
    [query setObject:kSecClassInternetPassword forKey:kSecClass];
    
    if([[self server] length])
    {
        [query setObject:[self server] forKey:kSecAttrServer];
    }
    
    if([[self securityDomain] length])
    {
        [query setObject:[self securityDomain] forKey:kSecAttrSecurityDomain];
    }
    
    if([[self account] length])
    {
        [query setObject:[self account] forKey:kSecAttrAccount];
    }
    
    if([[self path] length])
    {
        [query setObject:[self path] forKey:kSecAttrPath];
    }
    
    [query setObject:[NSNumber numberWithInt:[self port]] forKey:kSecAttrPort];
    
    if([self protocol])
    {
        [query setObject:[self protocol] forKey:kSecAttrProtocol];
    }
    
    if([self authenticationType])
    {
        [query setObject:[self authenticationType] forKey:kSecAttrAuthenticationType];
    }
    
	OSStatus resultStatus = SecItemDelete((CFDictionaryRef)query);
    
	if (resultStatus != noErr)
	{
#if DEBUG
        NSLog(@"Error (%@) - %@ query %@",NSStringFromSelector(_cmd),[NSError errorWithDomain:NSOSStatusErrorDomain code:resultStatus userInfo:nil],query);
#endif
	}else{
        removed = YES;
    }
    
    return removed;
}


+ (NSArray *)internetKeychainItemsForServer:(NSString *)server
                             securityDomain:(NSString *)securityDomain
                                       path:(NSString *)path
                                       port:(UInt16)port
                                   protocol:(CFTypeRef)protocol
                         authenticationType:(CFTypeRef)authenticationType{

    NSMutableArray *genericKeychainItems = nil;

    NSMutableDictionary *query = [NSMutableDictionary dictionary];
    
    [query setObject:kSecClassInternetPassword forKey:kSecClass];
    
    if([server length])
    {
        [query setObject:server forKey:kSecAttrServer];
    }
    
    if([securityDomain length])
    {
        [query setObject:securityDomain forKey:kSecAttrSecurityDomain];
    }
    
    if([path length])
    {
        [query setObject:path forKey:kSecAttrPath];
    }
    
    [query setObject:[NSNumber numberWithInt:port] forKey:kSecAttrPort];
    
    if(protocol)
    {
        [query setObject:protocol forKey:kSecAttrProtocol];
    }
    
    if(authenticationType)
    {
        [query setObject:authenticationType forKey:kSecAttrAuthenticationType];
    }
    
    [query setObject:kSecMatchLimitAll forKey:kSecMatchLimit];
    
    [query setObject:@YES forKey:kSecReturnAttributes];
    
    NSMutableDictionary *queryResults = nil;
    OSStatus returnStatus = SecItemCopyMatching((CFDictionaryRef)query, (CFTypeRef *)&queryResults);
    
    if (returnStatus != noErr)
    {
#if DEBUG
        NSLog(@"Error (%@) - %@ query %@",NSStringFromSelector(_cmd),[NSError errorWithDomain:NSOSStatusErrorDomain code:returnStatus userInfo:nil],query);
#endif
    }else{
        
        genericKeychainItems = [NSMutableArray array];
        
        CFArrayRef secItems = (CFArrayRef)queryResults;
        
        NSUInteger numberOfSecItems = CFArrayGetCount(secItems);
        
        for (NSUInteger i = 0; i < numberOfSecItems; i++){
            
            NSDictionary *secItem = CFArrayGetValueAtIndex(secItems,i);
            
            MCSMInternetKeychainItem *internetKeychainItem = [self internetKeychainItemForServer:[secItem objectForKey:kSecAttrServer]
                                                                                  securityDomain:[secItem objectForKey:kSecAttrSecurityDomain]
                                                                                         account:[secItem objectForKey:kSecAttrAccount]
                                                                                            path:[secItem objectForKey:kSecAttrPath]
                                                                                            port:[[secItem objectForKey:kSecAttrPort] intValue]
                                                                                        protocol:[secItem objectForKey:kSecAttrProtocol]
                                                                              authenticationType:[secItem objectForKey:kSecAttrAuthenticationType]];
                                                    
            if(internetKeychainItem)
            {
                [genericKeychainItems addObject:internetKeychainItem];
            }
        }
        
        
    }
    
    
    return genericKeychainItems;
}


+ (MCSMInternetKeychainItem *)internetKeychainItemForServer:(NSString *)server
                                             securityDomain:(NSString *)securityDomain
                                                    account:(NSString *)account
                                                       path:(NSString *)path
                                                       port:(UInt16)port
                                                   protocol:(CFTypeRef)protocol
                                         authenticationType:(CFTypeRef)authenticationType{
    
    NSMutableDictionary *query = [NSMutableDictionary dictionary];
    
    [query setObject:kSecClassInternetPassword forKey:kSecClass];
    
    if([server length])
    {
        [query setObject:server forKey:kSecAttrServer];
    }
    
    if([securityDomain length])
    {
        [query setObject:securityDomain forKey:kSecAttrSecurityDomain];
    }
    
    if([account length])
    {
        [query setObject:account forKey:kSecAttrAccount];
    }
    
    if([path length])
    {
        [query setObject:path forKey:kSecAttrPath];
    }
    
    [query setObject:[NSNumber numberWithInt:port] forKey:kSecAttrPort];
    
    if(protocol)
    {
        [query setObject:protocol forKey:kSecAttrProtocol];
    }
    
    if(authenticationType)
    {
        [query setObject:authenticationType forKey:kSecAttrAuthenticationType];
    }
    
    [query setObject:@YES forKey:kSecReturnAttributes];
    [query setObject:@YES forKey:kSecReturnData];
    
    NSMutableDictionary *results = nil;
    OSStatus returnStatus = SecItemCopyMatching((CFDictionaryRef)query, (CFTypeRef *)&results);
    
    MCSMInternetKeychainItem *internetKeychainItem = nil;
    
    if (returnStatus != noErr)
    {
#if DEBUG
        NSLog(@"Error (%@) - %@ query %@",NSStringFromSelector(_cmd),[NSError errorWithDomain:NSOSStatusErrorDomain code:returnStatus userInfo:nil],query);
#endif
    }else{
        
        NSData *passwordData = [results objectForKey:kSecValueData];
        
        NSString *password = [[NSString alloc] initWithBytes:[passwordData bytes]
                                                      length:[passwordData length]
                                                    encoding:NSUTF8StringEncoding];
        
        internetKeychainItem = [self _internetKeychainItemWithServer:[results objectForKey:kSecAttrServer]
                                                      securityDomain:[results objectForKey:kSecAttrSecurityDomain]
                                                             account:[results objectForKey:kSecAttrAccount]
                                                                path:[results objectForKey:kSecAttrPath]
                                                                port:[[results objectForKey:kSecAttrPort] intValue]
                                                            protocol:[results objectForKey:kSecAttrProtocol]
                                                  authenticationType:[results objectForKey:kSecAttrAuthenticationType]
                                                            password:password];
       [password release];
        
        
    }
    
    [results release];
    
    return internetKeychainItem;
}



+ (MCSMInternetKeychainItem *)internetKeychainItemWithServer:(NSString *)server
                                              securityDomain:(NSString *)securityDomain
                                                     account:(NSString *)account
                                                        path:(NSString *)path
                                                        port:(UInt16)port
                                                    protocol:(CFTypeRef)protocol
                                          authenticationType:(CFTypeRef)authenticationType
                                                    password:(NSString *)password
{
    
    NSMutableDictionary *query = [NSMutableDictionary dictionary];
    
    [query setObject:kSecClassInternetPassword forKey:kSecClass];
    
    if([server length])
    {
        [query setObject:server forKey:kSecAttrServer];
    }
    
    if([securityDomain length])
    {
        [query setObject:securityDomain forKey:kSecAttrSecurityDomain];
    }
    
    if([account length])
    {
        [query setObject:account forKey:kSecAttrAccount];
    }
    
    if([path length])
    {
        [query setObject:path forKey:kSecAttrPath];
    }
    
    [query setObject:[NSNumber numberWithInt:port] forKey:kSecAttrPort];
    
    if(protocol)
    {
        [query setObject:protocol forKey:kSecAttrProtocol];
    }
    
    if(authenticationType)
    {
        [query setObject:authenticationType forKey:kSecAttrAuthenticationType];
    }
    
    [query setObject:[password dataUsingEncoding:NSUTF8StringEncoding] forKey:kSecValueData];
    
    OSStatus returnStatus = SecItemAdd((CFDictionaryRef)query, NULL);
    
    MCSMInternetKeychainItem *internetKeychainItem = nil;
    
    if (returnStatus)
    {
#if DEBUG
        NSLog(@"Error (%@) - %@ query %@",NSStringFromSelector(_cmd),[NSError errorWithDomain:NSOSStatusErrorDomain code:returnStatus userInfo:nil],query);
#endif
        
    }else{
        
        internetKeychainItem = [self internetKeychainItemForServer:server
                                                    securityDomain:securityDomain
                                                           account:account
                                                              path:path
                                                              port:port
                                                          protocol:protocol
                                                authenticationType:authenticationType];

    }
    
    return internetKeychainItem;
}

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
                                                                          account:[[[NSBundle mainBundle] infoDictionary] objectForKey:@"CFBundleIdentifier"]
                                                                          password:UUIDString];
    
}
+ (MCSMApplicationUUIDKeychainItem *)applicationUUIDKeychainItem{
    
    return  (MCSMApplicationUUIDKeychainItem *)[self genericKeychainItemForService:MCSMApplicationUUIDKeychainItemService
                                                                          account:[[[NSBundle mainBundle] infoDictionary] objectForKey:@"CFBundleIdentifier"]];
    
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
    return [NSString stringWithFormat:@"%@ service:%@ account:%@ uuid:%@",NSStringFromClass([self class]),self.service,self.account,self.UUID];
}


- (NSString *)UUID{
    return self.password;
}

@end