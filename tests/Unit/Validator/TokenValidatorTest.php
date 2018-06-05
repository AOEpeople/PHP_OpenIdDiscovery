<?php

namespace Unit\Validator;

use aoepeople\OpenIdDiscovery\OpenIdDiscovery;
use aoepeople\OpenIdDiscovery\Validator\TokenValidator;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use PHPUnit\Framework\TestCase;


/**
 * Class TokenValidatorTest
 *
 * @package  aoepeople/OpenIdDiscovery
 * @author   AOE People <dev@aoe.com>
 * @license  none none
 * @link     www.aoe.com
 */
class TokenValidatorTest extends TestCase
{
    /** @var string */
    private $url;

    /** @var OpenIdDiscovery */
    private $openIdDiscovery;

    /**
     * setUp
     */
    protected function setUp()
    {
        $this->url = './tests/Unit/fixtures/autodiscovery.json';
        $this->openIdDiscovery = new OpenIdDiscovery($this->url);
    }

    /**
     * @test
     * @expectedException \Exception
     * @expectedExceptionMessage No certificate provided for token kid
     * @throws \Exception
     */
    public function testInvalidToken()
    {
        $validator = new TokenValidator(
            $this->createTokenString('invalid'),
            $this->openIdDiscovery->getCertKeyData()
        );

        $validator->isSignedCorrect();
    }

    /**
     * @test
     * @throws \Exception
     */
    public function testValidToken()
    {
        $validator = new TokenValidator(
            $this->createTokenString('not_signed'),
            $this->openIdDiscovery->getCertKeyData()
        );

        $this->assertFalse(
            $validator->isSignedCorrect(),
            "token is not signed correct"
        );
    }

    /**
     * Get a token string
     * @param string $kid KID
     * @return string
     */
    protected function createTokenString($kid)
    {
        $builder = new Builder();
        $builder->setHeader('alg', 'RS256')
            ->setHeader('kid', $kid)
            ->sign(new Sha256(), file_get_contents('./tests/Unit/fixtures/private.rsa'));


        return $builder->getToken();
    }
}
