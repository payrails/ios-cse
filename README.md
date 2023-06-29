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
