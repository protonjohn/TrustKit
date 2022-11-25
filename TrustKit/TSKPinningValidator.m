/*
 
 TSKPinningValidator.m
 TrustKit
 
 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

#import "TSKPinningValidator.h"
#import "TSKTrustKitConfig.h"
#import "TSKTrustDecision.h"
#import "TSKPinningValidatorResult.h"
#import "Pinning/TSKSPKIHashCache.h"
#import "Pinning/ssl_pin_verifier.h"
#import "configuration_utils.h"
#import "TrustKit.h"
#import "TSKLog.h"
#import "TSKPinningValidator_Private.h"

static const char kTSKPinFailureReporterQueueLabel[] = "com.datatheorem.trustkit.reporterqueue";

// A shared hash cache for use by all TrustKit instances
static TSKSPKIHashCache *sharedHashCache;

@interface TSKPinningValidator ()

@property (nonatomic) TSKSPKIHashCache *spkiHashCache;

/**
 The queue use when invoking the `validationCallback`.
 */
@property (nonatomic, readonly, nonnull) dispatch_queue_t validationCallbackQueue;

@end

@implementation TSKPinningValidator

+ (BOOL)allowsAdditionalTrustAnchors
{
    static const BOOL allowAdditionalTrustAnchors = {
#if DEBUG == 1
        YES
#else
        NO
#endif
    };
    return allowAdditionalTrustAnchors;
}

#pragma mark Instance Methods

- (instancetype)initWithDomainPinningPolicies:(NSDictionary<NSString *,NSDictionary *> *)domainPinningPolicies
                ignorePinsForUserTrustAnchors:(BOOL)ignorePinsForUserTrustAnchors
{
    self = [super init];
    if (self) {
        static dispatch_once_t onceToken;
        dispatch_once(&onceToken, ^{
            sharedHashCache = [[TSKSPKIHashCache alloc] initWithIdentifier:kTSKSPKISharedHashCacheIdentifier];
        });

        // Create a dispatch queue for activating the reporter
        // We use a serial queue targeting the global default queue in order to ensure reports are sent one by one
        // even when a lot of pin failures are occurring, instead of spamming the global queue with events to process
        _validationCallbackQueue = dispatch_queue_create(kTSKPinFailureReporterQueueLabel, DISPATCH_QUEUE_SERIAL);

        _domainPinningPolicies = domainPinningPolicies;
        _ignorePinsForUserTrustAnchors = ignorePinsForUserTrustAnchors;
        _spkiHashCache = sharedHashCache;
    }
    return self;
}

- (TSKTrustDecision)evaluateTrust:(SecTrustRef _Nonnull)serverTrust forHostname:(NSString * _Nonnull)serverHostname
{
    TSKTrustDecision finalTrustDecision = TSKTrustDecisionShouldBlockConnection;
    
    if ((serverTrust == NULL) || (serverHostname == nil))
    {
        TSKLog(@"Pin validation error - invalid parameters for %@", serverHostname);
        return finalTrustDecision;
    }
    CFRetain(serverTrust);
    
    // Register start time for duration computations
    NSTimeInterval validationStartTime = [NSDate timeIntervalSinceReferenceDate];
    
    // Retrieve the pinning configuration for this specific domain, if there is one
    NSString *domainConfigKey = getPinningConfigurationKeyForDomain(serverHostname, self.domainPinningPolicies);
    if (domainConfigKey == nil)
    {
        // The domain has no pinning policy: nothing to do/validate
        finalTrustDecision = TSKTrustDecisionDomainNotPinned;
    }
    else
    {
        // This domain has a pinning policy
        NSDictionary *domainConfig = self.domainPinningPolicies[domainConfigKey];
        
        // Has the pinning policy expired?
        NSDate *expirationDate = domainConfig[kTSKExpirationDate];
        if (expirationDate != nil && [expirationDate compare:[NSDate date]] == NSOrderedAscending)
        {
            // Yes the policy has expired
            finalTrustDecision = TSKTrustDecisionDomainNotPinned;
        }
        else if ([domainConfig[kTSKExcludeSubdomainFromParentPolicy] boolValue])
        {
            // This is a subdomain that was explicitly excluded from the parent domain's policy
            finalTrustDecision = TSKTrustDecisionDomainNotPinned;
        }
        else
        {
            //ignore self signed domain check. will verify the pinned key only
            BOOL forceSubdomain = [domainConfig[kForceSubdomains] boolValue];
            // The domain has a pinning policy that has not expired
            // Look for one the configured public key pins in the server's evaluated certificate chain
            TSKTrustEvaluationResult validationResult = verifyPublicKeyPin(serverTrust,
                                                                           serverHostname,
                                                                           domainConfig[kTSKPublicKeyHashes],
                                                                           self.spkiHashCache,
                                                                           forceSubdomain == NO);
            if (validationResult == TSKTrustEvaluationSuccess)
            {
                // Pin validation was successful
                TSKLog(@"Pin validation succeeded for %@", serverHostname);
                finalTrustDecision = TSKTrustDecisionShouldAllowConnection;
            }
            else
            {
                // Pin validation failed
                TSKLog(@"Pin validation failed for %@", serverHostname);
#if !TARGET_OS_IPHONE
                if ((validationResult == TSKTrustEvaluationFailedUserDefinedTrustAnchor)
                    && (self.ignorePinsForUserTrustAnchors))
                {
                    // OS-X only: user-defined trust anchors can be whitelisted (for corporate proxies, etc.) so don't send reports
                    TSKLog(@"Ignoring pinning failure due to user-defined trust anchor for %@", serverHostname);
                    finalTrustDecision = TSKTrustDecisionShouldAllowConnection;
                }
                else
#endif
                {
                    if (validationResult == TSKTrustEvaluationFailedNoMatchingPin)
                    {
                        // Is pinning enforced?
                        if ([domainConfig[kTSKEnforcePinning] boolValue] == YES)
                        {
                            // Yes - Block the connection
                            finalTrustDecision = TSKTrustDecisionShouldBlockConnection;
                        }
                        else
                        {
                            finalTrustDecision = TSKTrustDecisionShouldAllowConnection;
                        }
                    }
                    else
                    {
                        // Misc pinning errors (such as invalid certificate chain) - block the connection
                        finalTrustDecision = TSKTrustDecisionShouldBlockConnection;
                    }
                }
            }
            
            // Send a notification after all validation is done; this will also trigger a report if pin validation failed
            if (self.validationCallbackQueue && self.validationCallback) {
                NSTimeInterval validationDuration = [NSDate timeIntervalSinceReferenceDate] - validationStartTime;
                TSKPinningValidatorResult *result = [[TSKPinningValidatorResult alloc] initWithServerHostname:serverHostname
                                                                                                  serverTrust:serverTrust
                                                                                             validationResult:validationResult
                                                                                           finalTrustDecision:finalTrustDecision
                                                                                           validationDuration:validationDuration];
                dispatch_async(self.validationCallbackQueue, ^{
                    self.validationCallback(result, domainConfigKey, domainConfig);
                });
            }
        }
    }
    CFRelease(serverTrust);
    
    return finalTrustDecision;
}


- (BOOL)handleChallenge:(NSURLAuthenticationChallenge * _Nonnull)challenge completionHandler:(void (^ _Nonnull)(NSURLSessionAuthChallengeDisposition disposition, NSURLCredential * _Nullable credential))completionHandler
{
    BOOL wasChallengeHandled = NO;
    if ([challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust])
    {
        // Check the trust object against the pinning policy
        SecTrustRef serverTrust = challenge.protectionSpace.serverTrust;
        NSString *serverHostname = challenge.protectionSpace.host;
        
        TSKTrustDecision trustDecision = [self evaluateTrust:serverTrust forHostname:serverHostname];
        if (trustDecision == TSKTrustDecisionShouldAllowConnection)
        {
            // Success
            wasChallengeHandled = YES;
            completionHandler(NSURLSessionAuthChallengeUseCredential, [NSURLCredential credentialForTrust:serverTrust]);
        }
        else if (trustDecision == TSKTrustDecisionDomainNotPinned)
        {
            // Domain was not pinned; we need to do the default validation to avoid disabling SSL validation for all non-pinned domains
            wasChallengeHandled = YES;
            completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, NULL);
        }
        else
        {
            // Pinning validation failed - block the connection
            wasChallengeHandled = YES;
            completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, NULL);
        }
    }
    return wasChallengeHandled;
}

@end
