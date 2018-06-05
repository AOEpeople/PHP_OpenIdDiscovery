<?php
namespace Unit;

use aoepeople\OpenIdDiscovery\OpenIdDiscovery;

/**
 * Class OpenIdDiscoveryTest
 *
 * @package  aoepeople/OpenIdDiscovery
 * @author   AOE People <dev@aoe.com>
 * @license  none none
 * @link     www.aoe.com
 */
class OpenIdDiscoveryTest extends \PHPUnit\Framework\TestCase
{
    /**
     * @var string
     */
    private $url;

    /**
     * Set up
     */
    protected function setUp()
    {
        $this->url = './tests/Unit/fixtures/autodiscovery.json';
    }

    /**
     * @test
     */
    public function testInstantiation()
    {
        $openIdDiscovery = new OpenIdDiscovery($this->url);
        $this->assertNotNull(
            $openIdDiscovery,
            "OpenIdDiscovery could be instantiated"
        );
    }

    /**
     * @throws \Exception
     */
    public function testCertKeyData()
    {
        $openIdDiscovery = new OpenIdDiscovery($this->url);

        $certKeyData = $openIdDiscovery->getCertKeyData();
        $this->assertInternalType('array', $certKeyData);
    }
}
