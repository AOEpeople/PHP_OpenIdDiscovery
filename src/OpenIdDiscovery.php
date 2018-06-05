<?php
namespace aoepeople\OpenIdDiscovery;

/**
 * Class OpenIdDiscovery
 *
 * @package aoepeople\OpenIdDiscovery
 * @author   AOE People <dev@aoe.com>
 * @license  none none
 * @link     www.aoe.com
 */
class OpenIdDiscovery {

    /**
     * @var string
     */
    private $url;

    /**
     * @var \stdClass
     */
    protected $discoveredJson;

    /**
     * OpenIdDiscovery constructor.
     * @param string $url Autodiscovery URL
     */
    function __construct($url)
    {
        $this->url = $url;
    }

    /**
     * Lazy getter for the discovered json
     *
     * @return \stdClass
     * @throws \Exception
     */
    protected function getDiscoveredJson()
    {
        if ($this->discoveredJson) {
            return $this->discoveredJson;
        }


        $content = file_get_contents($this->url);
        if ($content === false) {
            throw new \Exception('Could not get autodiscovery url: ' . $this->url);
        }

        $json = json_decode($content);
        if ($json === NULL) {
            throw new \Exception('Could not parse autodiscovery url content into json: '.json_last_error());
        }
        $this->discoveredJson = $json;

        return $this->discoveredJson;
    }

    /**
     * @return Cert[]
     * @throws \Exception
     */
    public function getCertKeyData()  {

        $discoveredJson = $this->getDiscoveredJson();

        if (!isset($discoveredJson->jwks_uri)) {
            throw new \Exception('autodiscovery url is missing jwks_uri declaration');
        }
        $certContent = file_get_contents($discoveredJson->jwks_uri);
        if ($certContent === false) {
            throw new \Exception('Could not get cert url: ' . $discoveredJson->jwks_uri);
        }

        $certJson = json_decode($certContent);
        if ($certJson === NULL) {
            throw new \Exception('Could not parse cert url content into json: '.json_last_error());
        }

        /** @var Cert[] $result */
        $result = [];
        foreach ($certJson->keys as $certData) {
            $result[] = new Cert($certData);
        }

        return $result;
    }
}

