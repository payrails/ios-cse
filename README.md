# Payrails iOS CSE SDK

## Features

SDK provides client side encryption and tokenization on Payrails platform.

## Installation

### CocoaPods

Add `pod 'PayrailsCSE'` to your `Podfile`.
Run `pod install`.

## Usage example

```(swift)
import PayrailsCSE

let cse = PayrailsCSE(
    data: initResponse.data,
    version: initResponse.version
)

cse.tokenize(
    cardNumber: cardNumber,
    expiryMonth: expiryMonth,
    expiryYear: expiryYear,
    holderName: holderName,
    securityCode: securityCode,
    futureUsage: futureUsage,
    storeInstrument: storeInstrument,
    completion: {(result: Result<TokenizeResponse, Error>) in
        switch result {
        case .success(let response):
            debugPrint("tokenization request successful")
        case .failure(let error):
            debugPrint("tokenization request failed")
        }
    }
)
```
