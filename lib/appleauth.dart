part of masamune.signin.apple;

/// Sign in to Firebase using Apple SignIn.
class AppleAuth {
  /// Set options for authentication.
  ///
  /// [clientId]: Service ID created in Apple Developer Program.
  /// [redirectUri]: The same redirect URL that you registered for your Service ID.
  /// [PackageName] is replaced with the package name.
  static void initialize(
      {String clientId, String redirectUri, bool onlyIOS = false}) {
    _onlyIOS = onlyIOS;
    _clientId = clientId;
    _redirectUri = redirectUri;
  }

  /// Gets the options for the provider.
  static const AuthProviderOptions options = const AuthProviderOptions(
      id: "apple",
      provider: _provider,
      title: "Apple SignIn",
      text: "Sign in with your Apple account.");
  static Future<FirestoreAuth> _provider(
      BuildContext context, Duration timeout) {
    if (_onlyIOS && !Config.isIOS) {
      Log.error("Not supported on non-IOS platforms.");
      return Future.delayed(Duration.zero);
    }
    if (!_onlyIOS && (isEmpty(_clientId) || isEmpty(_redirectUri))) {
      Log.error("Unable to read required information.");
      return Future.delayed(Duration.zero);
    }
    return signIn(timeout: timeout);
  }

  static bool _onlyIOS = true;
  static String _clientId;
  static String _redirectUri;

  /// Sign in to Firebase using Apple SignIn.
  ///
  /// [protorol]: Protocol specification.
  /// [timeout]: Timeout time.
  static Future<FirestoreAuth> signIn(
      {String protocol, Duration timeout = Const.timeout}) {
    return FirestoreAuth.signInWithProvider(
        providerCallback: (timeout) async {
          try {
            PackageInfo info = await PackageInfo.fromPlatform();
            final AuthorizationCredentialAppleID appleResult =
                await SignInWithApple.getAppleIDCredential(
                    scopes: [
                      AppleIDAuthorizationScopes.email,
                      AppleIDAuthorizationScopes.fullName,
                    ],
                    webAuthenticationOptions:
                        (isNotEmpty(_clientId) && isNotEmpty(_redirectUri))
                            ? WebAuthenticationOptions(
                                clientId: _clientId,
                                redirectUri: Uri.parse(_redirectUri.replaceAll(
                                    "[PackageName]", info.packageName)),
                              )
                            : null);
            if (appleResult != null &&
                appleResult.authorizationCode != null &&
                appleResult.identityToken != null) {
              return OAuthProvider(providerId: "apple.com").getCredential(
                  idToken: appleResult.identityToken,
                  accessToken: appleResult.authorizationCode);
            } else {
              Log.error(
                  "Login failed because the authentication information cannot be found.");
              return Future.delayed(Duration.zero);
            }
          } catch (e) {
            Log.error(e.toString());
            return Future.delayed(Duration.zero);
          }
        },
        providerId: "apple.com",
        protocol: protocol,
        timeout: timeout);
  }
}
