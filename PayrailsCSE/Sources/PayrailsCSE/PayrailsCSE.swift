import Foundation
import JOSESwift

struct InitResponse: Codable {
    let version: String
    let data: String
}

struct Card: Codable {
    let holderName: String?
    let cardNumber: String
    let expiryMonth: String
    let expiryYear: String
    let securityCode: String?
}

struct TokenizationRequest: Codable {
    let id: UUID
    let holderReference: String
    let encryptedInstrumentDetails: String
    let futureUsage: FutureUsage?
    let storeInstrument: Bool?
}

enum FutureUsage: String, Codable {
    case recurring
    case cardOnFile
    case unscheduledCardOnFile
}

struct TokenizeResponse: Codable {
    let code: Int
    let instrument: Instrument?
    let errors: [PayrailsError]?
}

struct PayrailsCSE {
    var cseConfig: CSEConfiguration?
    
    init(initResponse: InitResponse) {
        let config = parseConfig(data: initResponse.data)
        cseConfig = config
    }
    
    func encryptCard(card: Card) throws -> String {
        let jsonCard = try JSONEncoder().encode(card)
        
        guard let cseConfig = cseConfig else {
            throw NSError(domain: "ConfigError", code: 0, userInfo: [NSLocalizedDescriptionKey: "Missing Config"])
        }

        let header = JWEHeader(keyManagementAlgorithm: .RSAOAEP256, contentEncryptionAlgorithm: .A256CBCHS512)
        
        let publicKey: SecKey = try getPublicKey(cseConfig.tokenization.publicKey)
        let encrypter = Encrypter(keyManagementAlgorithm: .RSAOAEP256, contentEncryptionAlgorithm: .A256CBCHS512, encryptionKey: publicKey)!
        let jwe = try! JWE(header: header, payload: Payload(jsonCard), encrypter: encrypter)
        
        return jwe.compactSerializedString
    }
    
    func tokenize(card: Card, futureUsage: FutureUsage? = nil, storeInstrument: Bool? = true, completion: @escaping ((Result<TokenizeResponse, Error>) -> Void)) throws -> Void {
        guard let cseConfig = cseConfig else {
            throw NSError(domain: "ConfigError", code: 0, userInfo: [NSLocalizedDescriptionKey: "Missing Config"])
        }
        let encryptedCard = try! encryptCard(card: card)
        guard let tokenizeURL = URL(string: cseConfig.tokenization.links.tokenize.href) else {
            throw NSError(domain: "URLParsingError", code: 0, userInfo: [NSLocalizedDescriptionKey: "Invalid URL"])
        }
        
        var request = URLRequest(url: tokenizeURL)
        request.httpMethod = cseConfig.tokenization.links.tokenize.method
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("Bearer \(cseConfig.token)", forHTTPHeaderField: "Authorization")
        request.setValue(UUID().uuidString, forHTTPHeaderField: "x-idempotency-key")
        
        let encoder = JSONEncoder()
        let jsonRequest = try encoder.encode(TokenizationRequest(
            id: cseConfig.tokenization.id,
            holderReference: cseConfig.holderReference,
            encryptedInstrumentDetails: encryptedCard,
            futureUsage: futureUsage,
            storeInstrument: storeInstrument
        ))
        request.httpBody = jsonRequest
        
        let task = URLSession.shared.dataTask(with: request) { data, response, error in
            do {
                if let error = error {
                    completion(.failure(error))
                }
                
                guard let httpResponse = response as? HTTPURLResponse else {
                    completion(.failure(NSError(domain: "NetworkError", code: 0, userInfo: [NSLocalizedDescriptionKey: "Invalid server response"])))
                    return
                }
                
                guard let data = data else {
                    completion(.success(TokenizeResponse(code: httpResponse.statusCode, instrument: nil, errors: nil)))
                    return
                }
                
                if httpResponse.statusCode == 201 {
                    let jsonResponse = try JSONDecoder().decode(Instrument.self, from: data)
                    completion(.success(TokenizeResponse(code: httpResponse.statusCode, instrument: jsonResponse, errors: nil)))
                    return
                } else {
                    let jsonResponse = try JSONDecoder().decode(PayrailsErrorList.self, from: data)
                    completion(.success(TokenizeResponse(code: httpResponse.statusCode, instrument: nil, errors: jsonResponse.errors)))
                    return
                }
            } catch let error as NSError {
                completion(.failure(error))
                return
            }
        }
        
        task.resume()
    }
    
    private func parseConfig(data: String) -> CSEConfiguration {
        guard let decodedData = Data(base64Encoded: data) else {
            fatalError("Failed to decode Base64 data")
        }
        
        guard let config = try? JSONDecoder().decode(CSEConfiguration.self, from: decodedData) else {
            fatalError("Failed to parse CSEConfiguration")
        }
        
        return config
    }
    
    private func getPublicKey(_ publicKey: String) throws -> SecKey {
        let publicKeyData = Data(base64Encoded: publicKey)!
        
        var error: Unmanaged<CFError>?
        
        guard let kCFBooleanFalse = kCFBooleanFalse else {
            throw NSError(domain: "Error", code: 0, userInfo: [NSLocalizedDescriptionKey: "kCFBooleanFalse is nil"])
        }
        
        let options: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits: 2048,
            kSecReturnPersistentRef: kCFBooleanFalse
        ]
            
        guard let publicKeyRef = SecKeyCreateWithData(publicKeyData as CFData, options as CFDictionary, &error) else {
            fatalError("Failed to create public key: \(error!)")
        }
        
        return publicKeyRef
    }
}

struct CSEConfiguration: Codable {
    let token: String
    let holderReference: String
    let tokenization: Tokenization
}

struct Tokenization: Codable {
    let id: UUID
    let publicKey: String
    let links: Links
}

struct Links: Codable {
    let tokenize: Link
}

struct Link: Codable {
    let method: String
    let href: String
}

struct Instrument: Codable {
    let id: UUID
    let createdAt: Instant
    let holderId: UUID
    let holderReference: String?
    let paymentMethod: PaymentMethodType
    let status: InstrumentStatus
    let description: String?
    let storeInstrument: Bool
    let data: InstrumentData
    let providerData: CodableValue?
    let futureUsage: FutureUsage
    let fingerprint: String?
}

struct InstrumentData: Codable {
    let bin: String?
    let holderName: String?
    let scheme: String?
    let suffix: String?
    let expiryMonth: String?
    let expiryYear: String?
    let paymentToken: String?
    let email: String?
}

enum InstrumentStatus: String, Codable {
    case created
    case enabled
    case disabled
    case deleted
    case invalid
    case transient
}

enum PaymentMethodType: String, Codable {
    case card
    case applePay
    case googlePay
    case klarna
    case klarnaPaynow
    case klarnaAccount
    case payPal
    case undetermined
}

struct PayrailsErrorList: Codable {
    let errors: [PayrailsError]
}

struct PayrailsError: Codable {
    let id: UUID
    let title: String
    let detail: String
    let meta: CodableValue?
}

struct CodableValue: Codable {
    let value: Any
    
    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        
        if let intValue = try? container.decode(Int.self) {
            value = intValue
        } else if let doubleValue = try? container.decode(Double.self) {
            value = doubleValue
        } else if let stringValue = try? container.decode(String.self) {
            value = stringValue
        } else if let boolValue = try? container.decode(Bool.self) {
            value = boolValue
        } else {
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "Unsupported CodableValue type")
        }
    }
    
    func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        
        if let intValue = value as? Int {
            try container.encode(intValue)
        } else if let doubleValue = value as? Double {
            try container.encode(doubleValue)
        } else if let stringValue = value as? String {
            try container.encode(stringValue)
        } else if let boolValue = value as? Bool {
            try container.encode(boolValue)
        } else {
            throw EncodingError.invalidValue(value, EncodingError.Context(codingPath: encoder.codingPath, debugDescription: "Unsupported CodableValue type"))
        }
    }
}

struct Instant: Codable {
    let epochSecond: Int
    let nano: Int
}
