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
     * @var string
     */
    protected $nonce;

    /**
     * @var string
     */
    protected $code_verifier;

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
     * Returns authorization parameters based on provided options.
     *
     * @param  array $options
     * @return array Authorization parameters
     */
    protected function getAuthorizationParameters(array $options)
    {
        if (empty($options['state'])) {
            $options['state'] = $this->getRandomState();
        }

        if (empty($options['scope'])) {
            $options['scope'] = $this->getDefaultScopes();
        }

        if (empty($options['nonce'])) {
            $options['nonce'] = $this->getRandomState();
        }

        if (empty($options['bail'])) {
            $options['bail'] = 1;
        }

        // PKCE
        $this->code_verifier = $this->getRandomState(80);

        // code_challenge の作成
        $hash = hash('sha256', $this->code_verifier);
        $code_challenge = self::base64UrlEncode(pack('H*', $hash));
        $code_challenge_method = 'S256';

        $options += [
            'code_challenge' => $code_challenge,
            'code_challenge_method' => $code_challenge_method,
            'response_type' => 'code',
        ];

        if (is_array($options['scope'])) {
            $separator = $this->getScopeSeparator();
            $options['scope'] = implode($separator, $options['scope']);
        }

        // Store the state as it may need to be accessed later on.
        $this->state = $options['state'];

        // Store the nonce as it may need to be accessed later on.
        $this->nonce = $options['nonce'];

        // Business code layer might set a different redirect_uri parameter
        // depending on the context, leave it as-is
        if (!isset($options['redirect_uri'])) {
            $options['redirect_uri'] = $this->redirectUri;
        }

        $options['client_id'] = $this->clientId;

        return $options;
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

    /**
     * Returns the current value of the state parameter.
     *
     * This can be accessed by the redirect handler during authorization.
     *
     * @return string
     */
    public function getNonce()
    {
        return $this->nonce;
    }

    /**
     * Returns the current value of the code_verifier parameter.
     *
     * This can be accessed by the redirect handler during authorization.
     *
     * @return string
     */
    public function getCodeVerifier()
    {
        return $this->code_verifier;
    }

    /**
     * Base64URL エンコードする
     * @param string $data エンコードする文字列
     * @return string
     */
    public static function base64UrlEncode($data)
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * Base64URL デコードする
     * @param string $data デコードする文字列
     * @return bool|string
     */
    public static function base64UrlDecode($data)
    {
        $replaced = str_replace(array('-', '_'), array('+', '/'), $data);
        $lack = strlen($replaced) % 4;
        if ($lack > 0) {
            $replaced .= str_repeat("=", 4 - $lack);
        }
        return base64_decode($replaced);
    }

    /**
     * ハッシュ値を生成する
     * @param $value
     * @return string
     */
    public static function generateHash($value)
    {
        $hash = hash('sha256', $value, true);
        $length = strlen($hash) / 2;
        $half_of_hash = substr($hash, 0, $length);
        return self::base64UrlEncode($half_of_hash);
    }

}