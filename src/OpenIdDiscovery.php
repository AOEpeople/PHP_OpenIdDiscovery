<?php
namespace aoepeople\OpenIdDiscovery;

use phpseclib\Crypt;
use phpseclib\Math;


class OpenIdDiscovery {

    /**
     * @var stdClass
     */
    protected $discoveredJson;

    function __construct($url)
    {
        $content = file_get_contents($url);
        if ($content === false) {
            throw new Exception('Could not get autodiscovery url: ' + $url);
        }

        $json = json_decode($content);
        if ($json === NULL) {
            throw new Exception('Could not parse autodiscovery url content into json: '.json_last_error());
        }
        $this->discoveredJson = $json;
    }

    /**
     * @return Cert
     * @throws Exception
     */
    public function getCertKeyData()  {

        if (!isset($this->discoveredJson->jwks_uri)) {
            throw new Exception('autodiscovery url is missing jwks_uri declaration');
        }
        $certContent = file_get_contents($this->discoveredJson->jwks_uri);
        if ($certContent === false) {
            throw new Exception('Could not get cert url: ' + $this->discoveredJson->jwks_uri);
        }

        $certJson = json_decode($certContent);
        if ($certJson === NULL) {
            throw new Exception('Could not parse cert url content into json: '.json_last_error());
        }

        if (!isset($certJson->keys[0])) {
            throw new Exception('No key declartion in cert url content');
        }

        return new Cert($certJson->keys[0]);
    }
}

