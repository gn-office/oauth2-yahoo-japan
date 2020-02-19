<?php

namespace GNOffice\OAuth2\Client\Provider;

use League\OAuth2\Client\Provider\AbstractProvider;
use Psr\Http\Message\ResponseInterface;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Tool\BearerAuthorizationTrait;
use League\OAuth2\Client\Provider\ResourceOwnerInterface;
use GNOffice\OAuth2\Client\Provider\Exception\YahooJapanIdentityProviderException;

class YahooJapan extends AbstractProvider
{

    protected $openid_configuration;

    /**
     * 各エンドポイントのURIとサポート機能を確認
     */
    public function discovery()
    {
        $method = self::METHOD_GET;
        $url = 'https://auth.login.yahoo.co.jp/yconnect/v2/.well-known/openid-configuration';
        $options = [];

        $request = $this->getRequest($method, $url, $options);

        $this->openid_configuration = $this->getParsedResponse($request);

        return $this->openid_configuration;
    }

    /**
     * Returns the base URL for authorizing a client.
     *
     * @return string
     */
    public function getBaseAuthorizationUrl()
    {
        $config = $this->discovery();
        return $config['authorization_endpoint'];
    }

    /**
     * Returns the base URL for requesting an access token.
     *
     * @param array $params
     * @return string
     */
    public function getBaseAccessTokenUrl(array $params)
    {
        $config = $this->discovery();
        return $config['token_endpoint'];
    }

    /**
     * Returns the URL for requesting the resource owner's details.
     *
     * @param AccessToken $token
     * @return string
     */
    public function getResourceOwnerDetailsUrl(AccessToken $token)
    {
        $config = $this->discovery();
        return $config['userinfo_endpoint'];
    }

    /**
     * Returns the default scopes used by this provider.
     *
     * This should only be the scopes that are required to request the details
     * of the resource owner, rather than all the available scopes.
     *
     * @return array
     */
    protected function getDefaultScopes()
    {
        $config = $this->discovery();
        return $config['scopes_supported'];
    }

    protected function getScopeSeparator()
    {
        return ' ';
    }

    /**
     * Checks a provider response for errors.
     *
     * @throws IdentityProviderException
     * @param  ResponseInterface $response
     * @param  array|string $data Parsed response data
     * @return void
     */
    protected function checkResponse(ResponseInterface $response, $data)
    {
        // TODO: Implement checkResponse() method.
    }

    /**
     * Generates a resource owner object from a successful resource owner
     * details request.
     *
     * @param  array $response
     * @param  AccessToken $token
     * @return ResourceOwnerInterface
     */
    protected function createResourceOwner(array $response, AccessToken $token)
    {
        // TODO: Implement createResourceOwner() method.
    }
}