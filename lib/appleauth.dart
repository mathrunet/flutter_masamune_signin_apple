part of masamune.signin.apple;

/// Sign in to Firebase using Apple SignIn.
class AppleAuth {
  /// Gets the options for the provider.
  static const AuthProviderOptions options = const AuthProviderOptions(
      id: "apple",
      provider: _provider,
      title: "Apple SignIn",
      text: "Sign in with your Apple account.");
  static Future<FirestoreAuth> _provider(
      BuildContext context, Duration timeout) {
    if (!Config.isIOS) {
      Log.error("Not supported on non-IOS platforms.");
      return Future.delayed(Duration.zero);
    }
    return signIn(timeout: timeout);
  }

  /// Sign in to Firebase using Apple SignIn.
  ///
  /// [protorol]: Protocol specification.
  /// [timeout]: Timeout time.
  static Future<FirestoreAuth> signIn(
      {String protocol, Duration timeout = Const.timeout}) {
    return FirestoreAuth.signInWithProvider(
        providerCallback: (timeout) async {
          AuthorizationResult result = await AppleSignIn.performRequests([
            AppleIdRequest(
              requestedScopes: [Scope.fullName],
              requestedOperation: OpenIdOperation.operationLogin,
            )
          ]);
          switch (result.status) {
            case AuthorizationStatus.cancelled:
              Log.error("Login canceled");
              return Future.delayed(Duration.zero);
            case AuthorizationStatus.error:
              Log.error(
                  "Login terminated with error: ${result.error.localizedDescription}");
              return Future.delayed(Duration.zero);
            default:
              break;
          }
          OAuthProvider provider = OAuthProvider(providerId: "apple.com");
          return provider.getCredential(
            idToken: String.fromCharCodes(result.credential.identityToken),
            accessToken:
                String.fromCharCodes(result.credential.authorizationCode),
          );
        },
        providerId: "apple.com",
        protocol: protocol,
        timeout: timeout);
  }
}
