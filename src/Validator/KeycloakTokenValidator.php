<?php
namespace aoepeople\OpenIdDiscovery;

use aoepeople\OpenIdDiscovery\Cert;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Parser;

class KeycloakTokenValidator {

    /**
     * @var Token
     */
    protected $token;

    /**
     * @var Cert
     */
    protected $cert;


    public function __construct($tokenContent, Cert $cert)
    {
        $this->token = (new Parser())->parse((string) $tokenContent); // Parses from a string
        $this->token->getHeaders(); // Retrieves the token header
        $this->token->getClaims(); // Retrieves the token claims

        $this->cert = $cert;
    }

    /**
     * @return Token
     */
    public function getToken() {
        return $this->token;
    }

    /**
     * @return bool
     */
    public function isExpired() {
        return $this->token->isExpired();
    }

    /**
     * @throws \Exception if key is invalid
     * @return bool
     */
    public function isSignedCorrect() {
        if ($this->cert->getKeyIdendifier() != $this->token->getHeader('kid')) {
            throw new \Exception('Key Idendifier Hints do not match!');
        }
        $signer = new Sha256();
        if (  $this->token->verify($signer,$this->cert->getPublicKey()))  {
            return true;
        } else {
            return false;
        }
    }
}