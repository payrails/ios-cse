# Payrails iOS CSE SDK

## Features

SDK provides client side encryption and tokenization on Payrails platform.

## Installation

### CocoaPods

Add `pod 'PayrailsCSE'` to your `Podfile`.
Run `pod install`.

### Swift Package Manager

Use `https://github.com/Payrails/ios-cse` as the repository URL

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

## Security Policy

### Reporting a Vulnerability

If you find any vulnerability in ios-cse, do not hesitate to _report them_.

1. Send the disclosure to security@payrails.com

2. Describe the vulnerability.

   If you have a fix, that is most welcome -- please attach or summarize it in your message!

3. We will evaluate the vulnerability and, if necessary, release a fix or mitigating steps to address it. We will contact you to let you know the outcome, and will credit you in the report.

   Please **do not disclose the vulnerability publicly** until a fix is released!

4. Once we have either a) published a fix, or b) declined to address the vulnerability for whatever reason, you are free to publicly disclose it.
