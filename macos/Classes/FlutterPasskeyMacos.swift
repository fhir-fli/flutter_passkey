// macos/Classes/FlutterPasskeyMacos.swift

import Cocoa
import Flutter
import AuthenticationServices

public class FlutterPasskeyMacos: NSObject, FlutterPlugin {

    // MARK: - Plugin Registration

    public static func register(with registrar: FlutterPluginRegistrar) {
        let channel = FlutterMethodChannel(name: "flutter_passkey", binaryMessenger: registrar.messenger())
        let instance = FlutterPasskeyMacos()
        registrar.addMethodCallDelegate(instance, channel: channel)
    }

    // MARK: - Method Call Handling

    public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        switch call.method {
        case "getPlatformVersion":
            result("macOS " + ProcessInfo.processInfo.operatingSystemVersionString)
        case "createCredential":
            if let args = call.arguments as? [String: Any],
               let options = args["options"] as? String {
                createCredential(options: options) { credential, error in
                    if let error = error {
                        result(FlutterError(code: "\(type(of: error))", message: "\(error)", details: nil))
                    } else {
                        result(credential)
                    }
                }
            } else {
                result(FlutterError(code: "InvalidParameter", message: "Options not found", details: nil))
            }
        case "getCredential":
            if let args = call.arguments as? [String: Any],
               let options = args["options"] as? String {
                getCredential(options: options) { credential, error in
                    if let error = error {
                        result(FlutterError(code: "\(type(of: error))", message: "\(error)", details: nil))
                    } else {
                        result(credential)
                    }
                }
            } else {
                result(FlutterError(code: "InvalidParameter", message: "Options not found", details: nil))
            }
        default:
            result(FlutterMethodNotImplemented)
        }
    }

    // MARK: - Credential Methods

    private func createCredential(options: String, completion: @escaping (_ credential: String?, _ error: Error?) -> Void) {
        // Parse the options JSON as needed; here we assume it contains similar information
        // as the iOS version. You can adapt the PublicKeyCredentialRequestOptions if necessary.
        do {
            let jsonData = options.data(using: .utf8)!
            let optionsDict = try JSONSerialization.jsonObject(with: jsonData, options: []) as? [String: Any] ?? [:]
            let publicKeyOptions = PublicKeyCredentialRequestOptions(optionsDict)
            let registrationRequest = try createPlatformPublicKeyCredentialRegistrationRequest(options: publicKeyOptions)
            
            // Create the authorization controller for macOS.
            let controller = ASAuthorizationController(authorizationRequests: [registrationRequest])
            let delegate = AuthControllerDelegateMacos(completion: completion)
            controller.delegate = delegate
            controller.presentationContextProvider = delegate
            
            controller.performRequests()
        } catch {
            completion(nil, error)
        }
    }
    
    private func getCredential(options: String, completion: @escaping (_ credential: String?, _ error: Error?) -> Void) {
        do {
            let jsonData = options.data(using: .utf8)!
            let optionsDict = try JSONSerialization.jsonObject(with: jsonData, options: []) as? [String: Any] ?? [:]
            let publicKeyOptions = PublicKeyCredentialRequestOptions(optionsDict)
            let assertionRequest = try createPlatformPublicKeyCredentialAssertionRequest(options: publicKeyOptions)
            
            let controller = ASAuthorizationController(authorizationRequests: [assertionRequest])
            let delegate = AuthControllerDelegateMacos(completion: completion)
            controller.delegate = delegate
            controller.presentationContextProvider = delegate
            
            controller.performRequests()
        } catch {
            completion(nil, error)
        }
    }
    
    // MARK: - Request Construction Helpers
    
    private func createPlatformPublicKeyCredentialRegistrationRequest(options: PublicKeyCredentialRequestOptions) throws -> ASAuthorizationPlatformPublicKeyCredentialRegistrationRequest {
        // Similar to the iOS implementation—adapt as needed.
        let rpId = try options.rpId
        let challenge = try options.challenge
        let userName = try options.userName
        let userId = try options.userId
        let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: rpId)
        let request = provider.createCredentialRegistrationRequest(challenge: challenge, name: userName, userID: userId)
        if let userVerification = options.userVerification {
            request.userVerificationPreference = userVerification
        }
        // Note: macOS may handle excluded credentials differently. Adapt if necessary.
        return request
    }
    
    private func createPlatformPublicKeyCredentialAssertionRequest(options: PublicKeyCredentialRequestOptions) throws -> ASAuthorizationPlatformPublicKeyCredentialAssertionRequest {
        let rpId = try options.rpId
        let challenge = try options.challenge
        let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: rpId)
        let request = provider.createCredentialAssertionRequest(challenge: challenge)
        if let userVerification = options.userVerification {
            request.userVerificationPreference = userVerification
        }
        if !options.allowCredentials.isEmpty {
            request.allowedCredentials = options.allowCredentials.map { ASAuthorizationPlatformPublicKeyCredentialDescriptor(credentialID: $0) }
        }
        return request
    }
}

// MARK: - Presentation & Delegate for macOS

// A helper delegate that conforms to both ASAuthorizationControllerDelegate
// and ASAuthorizationControllerPresentationContextProviding for macOS.
class AuthControllerDelegateMacos: NSObject, ASAuthorizationControllerDelegate, ASAuthorizationControllerPresentationContextProviding {
    
    private let completion: (_ credential: String?, _ error: Error?) -> Void

    init(completion: @escaping (_ credential: String?, _ error: Error?) -> Void) {
        self.completion = completion
    }
    
    // MARK: - ASAuthorizationControllerDelegate Methods
    
    func authorizationController(controller: ASAuthorizationController, didCompleteWithAuthorization authorization: ASAuthorization) {
        // Process the credential and convert it to a JSON string or other format as needed.
        // For example, you might generate a response dictionary similar to your iOS code.
        if let credential = generateCredentialResponse(from: authorization.credential) {
            completion(credential, nil)
        } else {
            completion(nil, NSError(domain: "FlutterPasskeyMacos", code: 1, userInfo: [NSLocalizedDescriptionKey: "Failed to generate credential response"]))
        }
    }
    
    func authorizationController(controller: ASAuthorizationController, didCompleteWithError error: Error) {
        completion(nil, error)
    }
    
    // MARK: - ASAuthorizationControllerPresentationContextProviding
    
    func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor {
        // On macOS, use the main window of NSApplication.
        // You might need to adjust this if your app manages windows differently.
        return NSApplication.shared.mainWindow ?? NSApplication.shared.windows.first!
    }
    
    // MARK: - Helper Method
    
    private func generateCredentialResponse(from credential: ASAuthorizationCredential) -> String? {
        // Convert the credential to a JSON string.
        // You can mirror the logic from your iOS implementation here.
        // This is a placeholder implementation.
        let responseDict: [String: Any] = [
            "credential": "dummy_response"  // Replace with actual conversion logic.
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: responseDict, options: []),
              let jsonString = String(data: data, encoding: .utf8) else {
            return nil
        }
        return jsonString
    }
}
