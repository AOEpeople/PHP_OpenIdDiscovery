<?php
namespace aoepeople\OpenIdDiscovery;

use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Math\BigInteger;

/**
 * Class Cert
 *
 * @package  aoepeople/OpenIdDiscovery
 * @author   AOE People <dev@aoe.com>
 * @license  none none
 * @link     www.aoe.com
 */
class Cert {

    /**
     * @var \stdClass
     */
    protected $keyData;

    public function __construct(\stdClass $keyData) {
        $this->keyData = $keyData;
    }

    /**
     * @return bool|string
     */
    public function getKeyIdendifier() {
        if (!isset($this->keyData->kid)) {
            return false;
        }

        return $this->keyData->kid;
    }
    /**
     * @return bool|string
     */
    public function getPublicKey() {
        $n = $this->keyData->n;
        $e = $this->keyData->e;

        $n = $this->base64url_decode($n);
        $e = $this->base64url_decode($e);

        $key = PublicKeyLoader::load([
            'e' => new BigInteger($e, 256),
            'n' => new BigInteger($n, 256)
        ]);

        return $key->toString('PKCS8');
    }

    /**
     * @param $data
     * @return string
     */
    protected function base64url_decode($data) {
        return base64_decode(str_pad(strtr($data, '-_', '+/'), strlen($data) % 4, '=', STR_PAD_RIGHT));
    }
}
