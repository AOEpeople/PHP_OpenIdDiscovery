<?php


use aoepeople\OpenIdDiscovery\OpenIdDiscovery;
use aoepeople\OpenIdDiscovery\KeycloakTokenValidator;

//TODO get your real AccessToken that you want to validate:
$token = file_get_contents("Testdata/accesstoken.jwt");

$autodiscovery = new OpenIdDiscovery("https://YOURKEYCLOAKDOMAIN/auth/realms/YOURREALM/.well-known/openid-configuration");
$tokenValidator = new KeycloakTokenValidator($token, $autodiscovery->getCertKeyData());

//Offline Validation: Checks if Token was signed be the public key of the realm - (that was autodiscovered)
if ( $tokenValidator->isSignedCorrect())  {
    echo "Is Valid"."\n";
} else {
    echo "Is NOT Valid"."\n";
}


if ( $tokenV->isExpired())  {
    echo "Is already expired!"."\n";
} else {
    echo "Is not expired"."\n";
}

