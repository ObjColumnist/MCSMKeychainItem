//
//  MCSMKeychainItem.m
//  MCSMSecurity
//
//  Created by Spencer MacDonald on 12/10/2011.
//  Copyright 2012 Square Bracket Software. All rights reserved.
//

#import "MCSMKeychainItem.h"

NSString * const MCSMKeychainItemQueryKey = @"MCSMKeychainItemQueryKey";

@interface MCSMKeychainItem ()

- (id)_initWithAccount:(NSString *)account
            attributes:(NSDictionary *)attributes
              password:(NSString *)password
                 error:(NSError *__autoreleasing *)error;
@end

@implementation MCSMKeychainItem {
	@private
	NSString *account_;
	NSDictionary *attributes_;
	NSString *password_;
}

@synthesize account = account_;
@synthesize attributes = attributes_;
@synthesize password = password_;

#pragma mark -

- (id)_initWithAccount:(NSString *)account
            attributes:(NSDictionary *)attributes
              password:(NSString *)password
                 error:(NSError **)error {
	if((self = [super init]))
	{
		account_ = [account copy];
		attributes_ = [attributes copy];
		password_ = [password copy];
	}
	return self;
}

#if TARGET_OS_MAC && !TARGET_IPHONE_SIMULATOR && !TARGET_OS_IPHONE

+ (void)lockKeychain {
	SecKeychainLock(NULL);
}

+ (void)unlockKeychain {
	SecKeychainUnlock(NULL, 0, NULL, NO);
}

#endif

- (NSString *)description {
	return [NSString stringWithFormat:@"%@ account:%@",NSStringFromClass([self class]),self.account];
}

#pragma mark -
#pragma mark Actions

- (id)objectForKeyedSubscript:(id <NSCopying>)key {
	return [self.attributes objectForKey:key];
}

- (BOOL)removeFromKeychainWithError:(NSError *__autoreleasing *)error {
	BOOL removed = NO;

	NSDictionary *query = [NSDictionary dictionaryWithObjectsAndKeys:[self account], kSecAttrAccount, kSecClassGenericPassword, kSecClass, nil];
	OSStatus resultStatus = SecItemDelete((__bridge CFDictionaryRef)query);

	if(resultStatus != noErr)
	{
		if(error == NULL)
		{
			NSError *newError __autoreleasing = nil;
			error = &newError;
		}
		NSDictionary *userInfo = @{ MCSMKeychainItemQueryKey : query };
		*error = [NSError errorWithDomain:NSOSStatusErrorDomain code:resultStatus userInfo:userInfo];
	}
	else
	{
		removed = YES;
	}

	return removed;
}

@end

@interface MCSMGenericKeychainItem ()

- (id)_initWithService:(NSString *)service
               account:(NSString *)account
            attributes:(NSDictionary *)attributes
              password:(NSString *)password
                 error:(NSError *__autoreleasing *)error;

+ (id)_genericKeychainItemWithService:(NSString *)service
                              account:(NSString *)account
                           attributes:(NSDictionary *)attributes
                             password:(NSString *)password
                                error:(NSError *__autoreleasing *)error;

@end

@implementation MCSMGenericKeychainItem {
	@private
	NSString *service_;
}

@synthesize service = service_;

- (id)_initWithService:(NSString *)service
               account:(NSString *)account
            attributes:(NSDictionary *)attributes
              password:(NSString *)password
                 error:(NSError *__autoreleasing *)error {
	if ((self = [super _initWithAccount:account attributes:attributes password:password error:error]))
	{
		service_ = [service copy];
	}
	return self;
}

+ (id)_genericKeychainItemWithService:(NSString *)service
                              account:(NSString *)account
                           attributes:(NSDictionary *)attributes
                             password:(NSString *)password
                                error:(NSError *__autoreleasing *)error {
	return [[self alloc] _initWithService:service
	                              account:account
	                           attributes:attributes
	                             password:password
	                                error:error];
}

- (NSString *)description {
	return [NSString stringWithFormat:@"%@ service:%@ account:%@",NSStringFromClass([self class]),self.service,self.account];
}

- (BOOL)removeFromKeychainWithError:(NSError *__autoreleasing *)error {
	BOOL removed = NO;

	NSMutableDictionary *query = [NSMutableDictionary dictionary];

	[query setObject:(__bridge id)(kSecClassGenericPassword) forKey:(__bridge id<NSCopying>)(kSecClass)];

	if([[self service] length])
	{
		[query setObject:[self service] forKey:(__bridge id<NSCopying>)(kSecAttrService)];
	}

	if([[self account] length])
	{
		[query setObject:[self account] forKey:(__bridge id<NSCopying>)(kSecAttrAccount)];
	}

	OSStatus resultStatus = SecItemDelete((__bridge CFDictionaryRef)query);

	if (resultStatus != noErr)
	{
		if(error == NULL)
		{
			NSError *newError __autoreleasing = nil;
			error = &newError;
		}

		NSDictionary *userInfo = @{ MCSMKeychainItemQueryKey : query };
		*error = [NSError errorWithDomain:NSOSStatusErrorDomain code:resultStatus userInfo:userInfo];
	}
	else
	{
		removed = YES;
	}

	return removed;
}

#pragma mark -

+ (NSArray *)genericKeychainItemsForService:(NSString *)service
                                 attributes:(NSDictionary *)attributes
                                      error:(NSError *__autoreleasing *)error {
	NSMutableArray *genericKeychainItems = nil;

	NSMutableDictionary *query = [NSMutableDictionary dictionary];

	[query setObject:(__bridge id)(kSecClassGenericPassword) forKey:(__bridge id<NSCopying>)(kSecClass)];

	if([service length])
	{
		[query setObject:service forKey:(__bridge id<NSCopying>)(kSecAttrService)];
	}

	if([[attributes allKeys] count])
	{
		[query addEntriesFromDictionary:attributes];
	}

	[query setObject:(__bridge id)(kSecMatchLimitAll) forKey:(__bridge id<NSCopying>)(kSecMatchLimit)];

	[query setObject:@YES forKey:(__bridge id<NSCopying>)(kSecReturnAttributes)];

	CFTypeRef resultsRef = nil;
	OSStatus returnStatus = SecItemCopyMatching((__bridge CFDictionaryRef)query, &resultsRef);
	NSArray *queryResults = (__bridge_transfer NSArray *)resultsRef;

	if (returnStatus != noErr)
	{
		if(error == NULL)
		{
			NSError *newError __autoreleasing = nil;
			error = &newError;
		}

		NSDictionary *userInfo = @{ MCSMKeychainItemQueryKey : query };
		*error = [NSError errorWithDomain:NSOSStatusErrorDomain code:returnStatus userInfo:userInfo];
	}
	else
	{
		genericKeychainItems = [NSMutableArray array];

		CFArrayRef secItems = (__bridge CFArrayRef)queryResults;

		NSUInteger numberOfSecItems = CFArrayGetCount(secItems);

		for (NSUInteger i = 0; i < numberOfSecItems; i++) {
			NSDictionary *secItem = CFArrayGetValueAtIndex(secItems,i);

			MCSMGenericKeychainItem *genericKeychainItem = nil;
			genericKeychainItem = [self genericKeychainItemForService:service
			                                                  account:[secItem objectForKey:(__bridge id)(kSecAttrAccount)]
			                                               attributes:secItem
			                                                    error:error];

			if(genericKeychainItem)
			{
				[genericKeychainItems addObject:genericKeychainItem];
			}
		}
	}

	return genericKeychainItems;
}

+ (MCSMGenericKeychainItem *)genericKeychainItemForService:(NSString *)service
                                                   account:(NSString *)account
                                                attributes:(NSDictionary *)attributes
                                                     error:(NSError *__autoreleasing *)error {
	NSMutableDictionary *query = [NSMutableDictionary dictionary];

	[query setObject:(__bridge id)(kSecClassGenericPassword) forKey:(__bridge id<NSCopying>)(kSecClass)];

	if([service length])
	{
		[query setObject:service forKey:(__bridge id<NSCopying>)(kSecAttrService)];
	}

	if([account length])
	{
		[query setObject:account forKey:(__bridge id<NSCopying>)(kSecAttrAccount)];
	}

	if([[attributes allKeys] count])
	{
		[query addEntriesFromDictionary:attributes];
	}

	[query setObject:(__bridge id)(kSecMatchLimitOne) forKey:(__bridge id<NSCopying>)(kSecMatchLimit)];
	[query setObject:@YES forKey:(__bridge id<NSCopying>)(kSecReturnAttributes)];
	[query setObject:@YES forKey:(__bridge id<NSCopying>)(kSecReturnData)];

	CFTypeRef resultsRef = nil;
	OSStatus returnStatus = SecItemCopyMatching((__bridge CFDictionaryRef)query, &resultsRef);
	NSDictionary *results = (__bridge_transfer NSDictionary *)resultsRef;

	MCSMGenericKeychainItem *genericKeychainItem = nil;
	if (returnStatus != noErr)
	{
		if(error == NULL)
		{
			NSError *newError __autoreleasing = nil;
			error = &newError;
		}

		NSDictionary *userInfo = @{ MCSMKeychainItemQueryKey : query };
		*error = [NSError errorWithDomain:NSOSStatusErrorDomain code:returnStatus userInfo:userInfo];
	}
	else
	{
		NSData *passwordData = [results objectForKey:(__bridge id)(kSecValueData)];

		NSString *password = [[NSString alloc] initWithBytes:[passwordData bytes]
		                                              length:[passwordData length]
		                                            encoding:NSUTF8StringEncoding];

		genericKeychainItem = [self _genericKeychainItemWithService:service
		                                                    account:[results objectForKey:(__bridge id)(kSecAttrAccount)]
		                                                 attributes:results
		                                                   password:password
		                                                      error:error];
	}

	return genericKeychainItem;
}

+ (MCSMGenericKeychainItem *)genericKeychainItemWithService:(NSString *)service
                                                    account:(NSString *)account
                                                 attributes:(NSDictionary *)attributes
                                                   password:(NSString *)password
                                                      error:(NSError *__autoreleasing *)error {
	NSMutableDictionary *query = [NSMutableDictionary dictionary];

	[query setObject:(__bridge id)(kSecClassGenericPassword) forKey:(__bridge id<NSCopying>)(kSecClass)];

	[query setObject:service forKey:(__bridge id<NSCopying>)(kSecAttrService)];
	[query setObject:account forKey:(__bridge id<NSCopying>)(kSecAttrAccount)];

	if([[attributes allKeys] count])
	{
		[query addEntriesFromDictionary:attributes];
	}

	[query setObject:[password dataUsingEncoding:NSUTF8StringEncoding] forKey:(__bridge id<NSCopying>)(kSecValueData)];

	OSStatus returnStatus = SecItemAdd((__bridge CFDictionaryRef)query, NULL);

	MCSMGenericKeychainItem *genericKeychainItem = nil;

	if (returnStatus)
	{
		if(error == NULL)
		{
			NSError *newError __autoreleasing = nil;
			error = &newError;
		}

		NSDictionary *userInfo = @{ MCSMKeychainItemQueryKey : query };
		*error = [NSError errorWithDomain:NSOSStatusErrorDomain code:returnStatus userInfo:userInfo];
	}
	else
	{
		genericKeychainItem = [self genericKeychainItemForService:service
		                                                  account:account
		                                               attributes:attributes
		                                                    error:error];
	}
	return genericKeychainItem;
}

@end

@implementation MCSMInternetKeychainItem {
	@private
	NSString *server_;
	NSString *securityDomain_;
	NSString *path_;
	NSUInteger port_;
	CFTypeRef protocol_;
	CFTypeRef authenticationType_;
}

@synthesize server = server_;
@synthesize securityDomain = securityDomain_;
@synthesize path = path_;
@synthesize port = port_;
@synthesize protocol = protocol_;
@synthesize authenticationType = authenticationType_;

- (id)     _initWithServer:(NSString *)server
            securityDomain:(NSString *)securityDomain
                   account:(NSString *)account
                      path:(NSString *)path
                      port:(NSUInteger)port
                  protocol:(CFTypeRef)protocol
        authenticationType:(CFTypeRef)authenticationType
                attributes:(NSDictionary *)attributes
                  password:(NSString *)password
                     error:(NSError *__autoreleasing *)error {
	if ((self = [super _initWithAccount:account attributes:attributes password:password error:error]))
	{
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
                                 port:(NSUInteger)port
                             protocol:(CFTypeRef)protocol
                   authenticationType:(CFTypeRef)authenticationType
                           attributes:(NSDictionary *)attributes
                             password:(NSString *)password
                                error:(NSError *__autoreleasing *)error {
	return [[self alloc] _initWithServer:server
	                      securityDomain:securityDomain
	                             account:account
	                                path:path
	                                port:port
	                            protocol:protocol
	                  authenticationType:authenticationType
	                          attributes:attributes
	                            password:password
	                               error:error];
}

- (void)dealloc {
	CFRelease(protocol_), protocol_ = NULL;
	CFRelease(authenticationType_), authenticationType_ = NULL;
}

#if TARGET_OS_MAC && !TARGET_IPHONE_SIMULATOR && !TARGET_OS_IPHONE

- (NSString *)description {
	return [NSString stringWithFormat:@"%@ server:%@ securityDomain:%@ account:%@ path:%@ port:%tu",NSStringFromClass([self class]),self.server,self.securityDomain, self.account,self.path,self.port];
}

#elif TARGET_OS_IPHONE

- (NSString *)description {
	return [NSString stringWithFormat:@"%@ server:%@ securityDomain:%@ account:%@ path:%@ port:%tu",NSStringFromClass([self class]),self.server,self.securityDomain, self.account,self.path,self.port];
}

#endif

- (BOOL)removeFromKeychainWithError:(NSError *__autoreleasing *)error {
	BOOL removed = NO;

	NSMutableDictionary *query = [NSMutableDictionary dictionary];

	[query setObject:(__bridge id)(kSecClassInternetPassword) forKey:(__bridge id<NSCopying>)(kSecClass)];

	if([[self server] length])
	{
		[query setObject:[self server] forKey:(__bridge id<NSCopying>)(kSecAttrServer)];
	}

	if([[self securityDomain] length])
	{
		[query setObject:[self securityDomain] forKey:(__bridge id<NSCopying>)(kSecAttrSecurityDomain)];
	}

	if([[self account] length])
	{
		[query setObject:[self account] forKey:(__bridge id<NSCopying>)(kSecAttrAccount)];
	}

	if([[self path] length])
	{
		[query setObject:[self path] forKey:(__bridge id<NSCopying>)(kSecAttrPath)];
	}

	[query setObject:[NSNumber numberWithUnsignedInteger:[self port]] forKey:(__bridge id<NSCopying>)(kSecAttrPort)];

	if([self protocol])
	{
		[query setObject:[self protocol] forKey:(__bridge id<NSCopying>)(kSecAttrProtocol)];
	}

	if([self authenticationType])
	{
		[query setObject:[self authenticationType] forKey:(__bridge id<NSCopying>)(kSecAttrAuthenticationType)];
	}

	OSStatus resultStatus = SecItemDelete((__bridge CFDictionaryRef)query);

	if (resultStatus != noErr)
	{
		if(error == NULL)
		{
			NSError *newError __autoreleasing = nil;
			error = &newError;
		}

		NSDictionary *userInfo = @{ MCSMKeychainItemQueryKey : query };
		*error = [NSError errorWithDomain:NSOSStatusErrorDomain code:resultStatus userInfo:userInfo];
	}
	else
	{
		removed = YES;
	}

	return removed;
}

+ (NSArray *)internetKeychainItemsForServer:(NSString *)server
                             securityDomain:(NSString *)securityDomain
                                       path:(NSString *)path
                                       port:(NSUInteger)port
                                   protocol:(CFTypeRef)protocol
                         authenticationType:(CFTypeRef)authenticationType
                                 attributes:(NSDictionary *)attributes
                                      error:(NSError *__autoreleasing *)error {
	NSMutableArray *internetKeychainItems = nil;

	NSMutableDictionary *query = [NSMutableDictionary dictionary];

	[query setObject:(__bridge id)(kSecClassInternetPassword) forKey:(__bridge id<NSCopying>)(kSecClass)];

	if([server length])
	{
		[query setObject:server forKey:(__bridge id<NSCopying>)(kSecAttrServer)];
	}

	if([securityDomain length])
	{
		[query setObject:securityDomain forKey:(__bridge id<NSCopying>)(kSecAttrSecurityDomain)];
	}

	if([path length])
	{
		[query setObject:path forKey:(__bridge id<NSCopying>)(kSecAttrPath)];
	}

	if(port > 0)
	{
		[query setObject:[NSNumber numberWithUnsignedInteger:port] forKey:(__bridge id<NSCopying>)(kSecAttrPort)];
	}

	if(protocol)
	{
		[query setObject:(__bridge id)(protocol) forKey:(__bridge id<NSCopying>)(kSecAttrProtocol)];
	}

	if(authenticationType)
	{
		[query setObject:(__bridge id)(authenticationType) forKey:(__bridge id<NSCopying>)(kSecAttrAuthenticationType)];
	}

	if([[attributes allKeys] count])
	{
		[query addEntriesFromDictionary:attributes];
	}

	[query setObject:(__bridge id)(kSecMatchLimitAll) forKey:(__bridge id<NSCopying>)(kSecMatchLimit)];

	[query setObject:@YES forKey:(__bridge id<NSCopying>)(kSecReturnAttributes)];

	CFTypeRef resultsRef = nil;
	OSStatus returnStatus = SecItemCopyMatching((__bridge CFDictionaryRef)query, &resultsRef);
    NSArray *queryResults = (__bridge_transfer NSArray *)resultsRef;

	if (returnStatus != noErr)
	{
		if(error == NULL)
		{
			NSError *newError __autoreleasing = nil;
			error = &newError;
		}

		NSDictionary *userInfo = @{ MCSMKeychainItemQueryKey : query };
		*error = [NSError errorWithDomain:NSOSStatusErrorDomain code:returnStatus userInfo:userInfo];
	}
	else
	{
		internetKeychainItems = [NSMutableArray array];

		CFArrayRef secItems = (__bridge CFArrayRef)queryResults;

		NSUInteger numberOfSecItems = CFArrayGetCount(secItems);

		for (NSUInteger i = 0; i < numberOfSecItems; i++) {
			NSDictionary *secItem = CFArrayGetValueAtIndex(secItems,i);

			MCSMInternetKeychainItem *internetKeychainItem = [self internetKeychainItemForServer:[secItem objectForKey:(__bridge id)(kSecAttrServer)]
			                                                                      securityDomain:[secItem objectForKey:(__bridge id)(kSecAttrSecurityDomain)]
			                                                                             account:[secItem objectForKey:(__bridge id)(kSecAttrAccount)]
			                                                                                path:[secItem objectForKey:(__bridge id)(kSecAttrPath)]
			                                                                                port:[[secItem objectForKey:(__bridge id)(kSecAttrPort)] intValue]
			                                                                            protocol:(__bridge CFTypeRef)([secItem objectForKey:(__bridge id)(kSecAttrProtocol)])
			                                                                  authenticationType:(__bridge CFTypeRef)([secItem objectForKey:(__bridge id)(kSecAttrAuthenticationType)])
			                                                                          attributes:secItem
			                                                                               error:error];

			if(internetKeychainItem)
			{
				[internetKeychainItems addObject:internetKeychainItem];
			}
		}
	}

	return internetKeychainItems;
}

+ (MCSMInternetKeychainItem *)internetKeychainItemForServer:(NSString *)server
                                             securityDomain:(NSString *)securityDomain
                                                    account:(NSString *)account
                                                       path:(NSString *)path
                                                       port:(NSUInteger)port
                                                   protocol:(CFTypeRef)protocol
                                         authenticationType:(CFTypeRef)authenticationType
                                                 attributes:(NSDictionary *)attributes
                                                      error:(NSError *__autoreleasing *)error {
	NSMutableDictionary *query = [NSMutableDictionary dictionary];

	[query setObject:(__bridge id)(kSecClassInternetPassword) forKey:(__bridge id<NSCopying>)(kSecClass)];

	if([server length])
	{
		[query setObject:server forKey:(__bridge id<NSCopying>)(kSecAttrServer)];
	}

	if([securityDomain length])
	{
		[query setObject:securityDomain forKey:(__bridge id<NSCopying>)(kSecAttrSecurityDomain)];
	}

	if([account length])
	{
		[query setObject:account forKey:(__bridge id<NSCopying>)(kSecAttrAccount)];
	}

	if([path length])
	{
		[query setObject:path forKey:(__bridge id<NSCopying>)(kSecAttrPath)];
	}

	if(port > 0)
	{
		[query setObject:[NSNumber numberWithUnsignedInteger:port] forKey:(__bridge id<NSCopying>)(kSecAttrPort)];
	}

	if(protocol)
	{
		[query setObject:(__bridge id)(protocol) forKey:(__bridge id<NSCopying>)(kSecAttrProtocol)];
	}

	if(authenticationType)
	{
		[query setObject:(__bridge id)(authenticationType) forKey:(__bridge id<NSCopying>)(kSecAttrAuthenticationType)];
	}

	if([[attributes allKeys] count])
	{
		[query addEntriesFromDictionary:attributes];
	}

	[query setObject:@YES forKey:(__bridge id<NSCopying>)(kSecReturnAttributes)];
	[query setObject:@YES forKey:(__bridge id<NSCopying>)(kSecReturnData)];

	CFTypeRef resultsRef = nil;
	OSStatus returnStatus = SecItemCopyMatching((__bridge CFDictionaryRef)query, &resultsRef);
	NSDictionary *results = (__bridge_transfer NSDictionary *)resultsRef;

	MCSMInternetKeychainItem *internetKeychainItem = nil;

	if (returnStatus != noErr)
	{
		if(error == NULL)
		{
			NSError *newError __autoreleasing = nil;
			error = &newError;
		}

		NSDictionary *userInfo = @{ MCSMKeychainItemQueryKey : query };
		*error = [NSError errorWithDomain:NSOSStatusErrorDomain code:returnStatus userInfo:userInfo];
	}
	else
	{
		NSData *passwordData = [results objectForKey:(__bridge id)(kSecValueData)];

		NSString *password = [[NSString alloc] initWithBytes:[passwordData bytes]
		                                              length:[passwordData length]
		                                            encoding:NSUTF8StringEncoding];

		internetKeychainItem = [self _internetKeychainItemWithServer:[results objectForKey:(__bridge id)(kSecAttrServer)]
		                                              securityDomain:[results objectForKey:(__bridge id)(kSecAttrSecurityDomain)]
		                                                     account:[results objectForKey:(__bridge id)(kSecAttrAccount)]
		                                                        path:[results objectForKey:(__bridge id)(kSecAttrPath)]
		                                                        port:[[results objectForKey:(__bridge id)(kSecAttrPort)] intValue]
		                                                    protocol:(__bridge CFTypeRef)([results objectForKey:(__bridge id)(kSecAttrProtocol)])
		                                          authenticationType:(__bridge CFTypeRef)([results objectForKey:(__bridge id)(kSecAttrAuthenticationType)])
		                                                  attributes:results
		                                                    password:password
		                                                       error:error];
	}

	return internetKeychainItem;
}

+ (MCSMInternetKeychainItem *)internetKeychainItemWithServer:(NSString *)server
                                              securityDomain:(NSString *)securityDomain
                                                     account:(NSString *)account
                                                        path:(NSString *)path
                                                        port:(NSUInteger)port
                                                    protocol:(CFTypeRef)protocol
                                          authenticationType:(CFTypeRef)authenticationType
                                                  attributes:(NSDictionary *)attributes
                                                    password:(NSString *)password
                                                       error:(NSError *__autoreleasing *)error {
	NSMutableDictionary *query = [NSMutableDictionary dictionary];

	[query setObject:(__bridge id)(kSecClassInternetPassword) forKey:(__bridge id<NSCopying>)(kSecClass)];

	if([server length])
	{
		[query setObject:server forKey:(__bridge id<NSCopying>)(kSecAttrServer)];
	}

	if([securityDomain length])
	{
		[query setObject:securityDomain forKey:(__bridge id<NSCopying>)(kSecAttrSecurityDomain)];
	}

	if([account length])
	{
		[query setObject:account forKey:(__bridge id<NSCopying>)(kSecAttrAccount)];
	}

	if([path length])
	{
		[query setObject:path forKey:(__bridge id<NSCopying>)(kSecAttrPath)];
	}

	if(port > 0)
	{
		[query setObject:[NSNumber numberWithUnsignedInteger:port] forKey:(__bridge id<NSCopying>)(kSecAttrPort)];
	}

	if(protocol)
	{
		[query setObject:(__bridge id)(protocol) forKey:(__bridge id<NSCopying>)(kSecAttrProtocol)];
	}

	if(authenticationType)
	{
		[query setObject:(__bridge id)(authenticationType) forKey:(__bridge id<NSCopying>)(kSecAttrAuthenticationType)];
	}

	if([[attributes allKeys] count])
	{
		[query addEntriesFromDictionary:attributes];
	}

	[query setObject:[password dataUsingEncoding:NSUTF8StringEncoding] forKey:(__bridge id<NSCopying>)(kSecValueData)];

	OSStatus returnStatus = SecItemAdd((__bridge CFDictionaryRef)query, NULL);

	MCSMInternetKeychainItem *internetKeychainItem = nil;

	if (returnStatus)
	{
		if(error == NULL)
		{
			NSError *newError __autoreleasing = nil;
			error = &newError;
		}

		NSDictionary *userInfo = @{ MCSMKeychainItemQueryKey : query };
		*error = [NSError errorWithDomain:NSOSStatusErrorDomain code:returnStatus userInfo:userInfo];
	}
	else
	{
		internetKeychainItem = [self internetKeychainItemForServer:server
		                                            securityDomain:securityDomain
		                                                   account:account
		                                                      path:path
		                                                      port:port
		                                                  protocol:protocol
		                                        authenticationType:authenticationType
		                                                attributes:attributes
		                                                     error:error];
	}

	return internetKeychainItem;
}

@end

NSString *const MCSMApplicationUUIDKeychainItemService = @"com.squarebracketsoftware.opensource.keychain.uuid.application";

@implementation MCSMApplicationUUIDKeychainItem

+ (MCSMApplicationUUIDKeychainItem *)generateApplicationUUIDKeychainItem {
	CFUUIDRef UUIDRef = CFUUIDCreate(kCFAllocatorDefault);
	CFStringRef UUIDStringRef = CFUUIDCreateString(kCFAllocatorDefault, UUIDRef);
	NSString *UUIDString = [NSString stringWithString:(__bridge NSString *)UUIDStringRef];
	CFRelease(UUIDStringRef);
	CFRelease(UUIDRef);

	return (MCSMApplicationUUIDKeychainItem *)[self genericKeychainItemWithService:MCSMApplicationUUIDKeychainItemService
	                                                                       account:[[[NSBundle mainBundle] infoDictionary] objectForKey:@"CFBundleIdentifier"]
	                                                                    attributes:nil
	                                                                      password:UUIDString
	                                                                         error:NULL];
}

+ (MCSMApplicationUUIDKeychainItem *)applicationUUIDKeychainItem {
	return (MCSMApplicationUUIDKeychainItem *)[self genericKeychainItemForService:MCSMApplicationUUIDKeychainItemService
	                                                                      account:[[[NSBundle mainBundle] infoDictionary] objectForKey:@"CFBundleIdentifier"]
	                                                                   attributes:nil
	                                                                        error:NULL];
}

+ (NSString *)applicationUUID {
	MCSMApplicationUUIDKeychainItem *applicationUDIDKeychainItem = [self applicationUUIDKeychainItem];

	if(!applicationUDIDKeychainItem)
	{
		applicationUDIDKeychainItem = [self generateApplicationUUIDKeychainItem];
	}

	return applicationUDIDKeychainItem.UUID;
}

- (NSString *)description {
	return [NSString stringWithFormat:@"%@ service:%@ account:%@ uuid:%@",NSStringFromClass([self class]),self.service,self.account,self.UUID];
}

- (NSString *)UUID {
	return self.password;
}

@end