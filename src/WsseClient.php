<?php
namespace KalkanCrypt;

use DOMDocument;
use DOMElement;
use KalkanCrypt\Exception\AdapterException;
use SoapClient;
use SoapVar;

class WsseClient extends SoapClient
{
    const ID_ATTR_NAME = "Id";
    const WSU_NS    = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd';
    const XML_NS    = 'http://www.w3.org/2000/xmlns/';

    private Provider $provider;

    public function __construct(Provider $provider, $options = [], ?string $wsdl = null)
    {
        $this->provider = $provider;
        parent::__construct($wsdl, $options);
    }

    /**
     * @throws AdapterException
     */
    public function __doRequest(string $request, string $location, string $action, int $version, bool $oneWay = false): ?string
    {
        $request = $this->signXml($request);
        return parent::__doRequest($request, $location, "", $version, $oneWay);
    }

    /**
     * Add id attribute to body and sign
     * @param string $xml
     * @return string
     * @throws AdapterException
     */
    private function signXml(string $xml): string
    {
        $id = uniqid();
        $doc = new DomDocument();

        $doc->loadXML($xml);
        /** @var DOMElement $body */
        $body = $doc->getElementsByTagName('Body')->item(0);
        $body->setAttribute(self::ID_ATTR_NAME, $id);
        $body->setAttributeNS(self::XML_NS,'xmlns:wsu', self::WSU_NS);
        $unsigned_xml = $doc->C14N();

        return $this->provider->signWSSE($unsigned_xml, $id);
    }
}