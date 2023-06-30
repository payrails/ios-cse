# Payrails iOS CSE SDK

## Features

SDK provides client side encryption and tokenization on Payrails platform.

## Usage example

```(swift)
import PayrailsCSE

let cse = PayrailsCSE()

let card = Card(
    holderReference: '123',
    cardNumber: '4111111111111111',
    expiryMonth: '11',
    expiryYear: '27',
    holderName: 'Card Holder',
    securityCode: 'secret'
)

cse.tokenize(card: card, futureUsage: .CardOnFile, storeInstrument: true, completion: {() in
  print('tokenize complete')
})
```

# Security Policy

## Reporting a Vulnerability

If you find any vulnerability in ios-cse, do not hesitate to _report them_.

1. Send the disclosure to security@payrails.com

2. Describe the vulnerability.

   If you have a fix, that is most welcome -- please attach or summarize it in your message!

3. We will evaluate the vulnerability and, if necessary, release a fix or mitigating steps to address it. We will contact you to let you know the outcome, and will credit you in the report.

   Please **do not disclose the vulnerability publicly** until a fix is released!

4. Once we have either a) published a fix, or b) declined to address the vulnerability for whatever reason, you are free to publicly disclose it.