/*
 
 TSKPinningValidator_Private.h
 TrustKit
 
 Copyright 2017 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

NS_ASSUME_NONNULL_BEGIN

@interface TSKPinningValidatorResult (Internal)

- (instancetype _Nullable)initWithServerHostname:(NSString *)serverHostname
                                     serverTrust:(SecTrustRef)serverTrust
                                validationResult:(TSKTrustEvaluationResult)validationResult
                              finalTrustDecision:(TSKTrustDecision)finalTrustDecision
                              validationDuration:(NSTimeInterval)validationDuration;

@end

NS_ASSUME_NONNULL_END
