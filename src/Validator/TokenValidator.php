<?php
namespace aoepeople\OpenIdDiscovery\Validator;

use aoepeople\OpenIdDiscovery\Cert;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Configuration;

/**
 * Class TokenValidator
 *
 * @package  aoepeople/OpenIdDiscovery
 * @author   AOE People <dev@aoe.com>
 * @license  none none
 * @link     www.aoe.com
 */
class TokenValidator {

    /**
     * @var Token
     */
    protected $token;

    /**
     * @var Cert[]
     */
    protected $certificates;

    /**
     * TokenValidator constructor.
     * @param string $tokenContent Token Content
     * @param Cert[] $cert         Certificates
     */
    public function __construct($tokenContent, array $cert)
    {
        $this->token = (new Parser(new JoseEncoder()))->parse((string) $tokenContent); // Parses from a string
        $this->certificates = $cert;
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
        return $this->token->isExpired(new \DateTime());
    }

    /**
     * @throws \Exception if key is invalid
     * @return bool
     */
    public function isSignedCorrect() {
        $certificate = $this->findCertificate($this->token->headers()->get('kid'));
        if (!$certificate) {
            throw new \Exception('No certificate provided for token kid');
        }

        $signer = new Sha256();
        $key = InMemory::plainText($certificate->getPublicKey());

        $configuration = Configuration::forSymmetricSigner($signer, $key);

        $constraint = new SignedWith($signer, $key);
        if ($configuration->validator()->validate($this->token, $constraint))  {
            return true;
        } else {
            return false;
        }
    }

    /**
     * Find a certificate matching kid
     * @param string $kid KID
     * @return Cert|null
     */
    protected function findCertificate($kid)
    {
        /** @var Cert $certificate */
        foreach ($this->certificates as $certificate) {
            if ($certificate->getKeyIdendifier() == $kid) {
                return $certificate;
            }
        }

        return null;
    }
}
