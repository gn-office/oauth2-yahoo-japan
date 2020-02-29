<?php

namespace GNOffice\OAuth2\Client\Provider;

use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Tool\BearerAuthorizationTrait;
use Psr\Http\Message\ResponseInterface;
use GNOffice\OAuth2\Client\Provider\Exception\YahooJapanIdentityProviderException;
use GNOffice\OAuth2\Client\Provider\Exception\InvalidTokenException;

class YahooJapan extends AbstractProvider
{

    use BearerAuthorizationTrait;

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
        // nonce
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
        ];

        // Store the nonce as it may need to be accessed later on.
        $this->nonce = $options['nonce'];

        // 親クラスのパラメータを追加
        $options = parent::getAuthorizationParameters($options);

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
        if ($response->getStatusCode() >= 400) {
            throw YahooJapanIdentityProviderException::clientException($response, $data);
        } elseif (isset($data['error'])) {
            throw YahooJapanIdentityProviderException::oauthException($response, $data);
        }
    }

    /**
     * Requests an access token using a specified grant and option set.
     *
     * @param  mixed $grant
     * @param  array $options
     * @return \League\OAuth2\Client\Token\AccessTokenInterface
     * @throws InvalidTokenException
     */
    public function getAccessToken($grant, array $options = [])
    {
        // nonce を取得
        $nonce = $options['nonce'];
        unset($options['nonce']);

        // 親クラスでアクセストークンを取得
        $token = parent::getAccessToken($grant, $options);

        $token_values = $token->getValues();
        $id_token = $token_values['id_token'];
        $access_token = $token->getToken();

        // アクセストークンを検証
        $verify_token = $this->verifyToken($id_token, $access_token, $nonce);
        if ($verify_token['is_valid']) {
            return $token;
        } else {
            throw new InvalidTokenException($verify_token['error']);
        }

    }

    /**
     * Generates a resource owner object from a successful resource owner
     * details request.
     *
     * @param  array $response
     * @param  AccessToken $token
     * @return YahooJapanResourceOwner
     */
    protected function createResourceOwner(array $response, AccessToken $token)
    {
        return new YahooJapanResourceOwner($response);
    }

    /**
     * Returns the current value of the nonce parameter.
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

    /**
     * トークンの検証を行う
     * @param string $jwt 取得した ID Token(JWT)
     * @param string $access_token 取得したアクセストークン
     * @param string $nonce トークン取得時に設定した nonce
     * @return array $verify_result
     */
    protected function verifyToken($jwt, $access_token, $nonce)
    {
        // JWT を分割
        list($header, $payload, $signature) = explode('.', $jwt);

        // Header から Key ID を取得
        $decoded_header = json_decode($this->base64UrlDecode($header), true);

        // Public Keysエンドポイントから Public Key を取得
        $method = self::METHOD_GET;
        $url = 'https://auth.login.yahoo.co.jp/yconnect/v2/public-keys';
        $options = [];

        $request = $this->getRequest($method, $url, $options);

        $data = $this->getParsedResponse($request);

        $public_key = $data[$decoded_header['kid']];

        $data = $header . '.' . $payload;
        $decoded_signature = $this->base64UrlDecode($signature);
        $public_key_id = openssl_pkey_get_public($public_key);
        if (!$public_key_id) {
            // failed to get public key resource
            $verify_result = [
                'is_valid' => false,
                'error' => 'Failed to get public key resource'
            ];
            return $verify_result;
        }
        $result = openssl_verify($data, $decoded_signature, $public_key_id, 'RSA-SHA256');
        openssl_free_key($public_key_id);
        if ($result !== 1) {
            // invalid signature
            $verify_result = [
                'is_valid' => false,
                'error' => 'Invalid signature'
            ];
            return $verify_result;
        }

        // Payload の検証
        $decoded_payload = json_decode($this->base64UrlDecode($payload), true);

        $config = $this->discovery();

        if ($decoded_payload['iss'] !== $config['issuer']) {
            // unmatched iss
            $verify_result = [
                'is_valid' => false,
                'error' => 'Unmatched iss'
            ];
            return $verify_result;
        }

        if ($decoded_payload['aud'][0] !== $this->clientId) {
            // unmatched aud
            $verify_result = [
                'is_valid' => false,
                'error' => 'Unmatched aud'
            ];
            return $verify_result;
        }

        if ($decoded_payload['nonce'] !== $nonce) {
            // unmatched nonce
            $verify_result = [
                'is_valid' => false,
                'error' => 'Unmatched nonce'
            ];
            return $verify_result;
        }

        // アクセストークンの検証
        if ($decoded_payload['at_hash'] !== $this->generateHash($access_token)) {
            // invalid access_token
            // unmatched aud
            $verify_result = [
                'is_valid' => false,
                'error' => 'Invalid Access Token(Token Substitution)'
            ];
            return $verify_result;
        }

        // 有効期限の確認
        if ($decoded_payload['exp'] < time()) {
            // token expired
            $verify_result = [
                'is_valid' => false,
                'error' => 'The ID Token expired'
            ];
            return $verify_result;
        }

        // 発行時刻の確認
        if ($decoded_payload['iat'] < time() - 600) {
            // invalid iat
            $verify_result = [
                'is_valid' => false,
                'error' => 'Invalid iat'
            ];
            return $verify_result;
        }

        $verify_result = [
            'is_valid' => true,
            'error' => null
        ];
        return $verify_result;
    }
}