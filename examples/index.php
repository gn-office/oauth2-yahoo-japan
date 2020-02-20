<?php
require_once '../vendor/autoload.php';

use GNOffice\OAuth2\Client\Provider\YahooJapan;

session_start();

$provider = new YahooJapan([
    'clientId' => 'dj00aiZpPVFXS1Z1bG9rTEE0MiZzPWNvbnN1bWVyc2VjcmV0Jng9ZjY-',
    'clientSecret' => 'vrXYgL1ruSTFNPy9XjIEUasJmrdrMWVIVkKE45cv',
    'redirectUri' => 'http://192.168.56.103/oauth2-yahoo-japan/examples/index.php',
]);

if (!isset($_GET['code'])) {

    // Fetch the authorization URL from the provider; this returns the
    // urlAuthorize option and generates and applies any necessary parameters
    // (e.g. state).
    $authorizationUrl = $provider->getAuthorizationUrl();

    // Get the state generated for you and store it to the session.
    $_SESSION['oauth2state'] = $provider->getState();

    // Get the nonce generated for you and store it to the session.
    $_SESSION['oauth2nonce'] = $provider->getNonce();

    // Get the code_verifier generated for you and store it to the session.
    $_SESSION['oauth2code_verifier'] = $provider->getCodeVerifier();

    // Redirect the user to the authorization URL.
    header('Location: ' . $authorizationUrl);
    exit;

// Check given state against previously stored one to mitigate CSRF attack
} elseif (empty($_GET['state']) || (isset($_SESSION['oauth2state']) && $_GET['state'] !== $_SESSION['oauth2state'])) {

    if (isset($_SESSION['oauth2state'])) {
        unset($_SESSION['oauth2state']);
    }

    exit('Invalid state');

} else {

    try {
        // Try to get an access token using the authorization code grant.
        $accessToken = $provider->getAccessToken('authorization_code', [
            'code' => $_GET['code'],
            'code_verifier' => $_SESSION['oauth2code_verifier'],
            'nonce' => $_SESSION['oauth2nonce']
        ]);

        // Using the access token, we may look up details about the
        // resource owner.
        $user = $provider->getResourceOwner($accessToken);

        // Use these details to create a new profile
        printf('Hello %s!', $user->getName());

    } catch (\League\OAuth2\Client\Provider\Exception\IdentityProviderException $e) {

        // Failed to get the access token or user details.
        exit($e->getMessage());

    }

    // Use this to interact with an API on the users behalf
    echo $accessToken->getToken();

}