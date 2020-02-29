<?php

namespace GNOffice\OAuth2\Client\Test\Provider;

use GNOffice\OAuth2\Client\Provider\YahooJapan;
use Mockery as m;
use ReflectionClass;
use PHPUnit\Framework\TestCase;

class YahooJapanTest extends TestCase
{
    protected $provider;

    protected static function getMethod($name)
    {
        $class = new ReflectionClass('GNOffice\OAuth2\Client\Provider\YahooJapan');
        $method = $class->getMethod($name);
        $method->setAccessible(true);
        return $method;
    }

    protected function setUp(): void
    {
        $this->provider = new YahooJapan([
            'clientId' => 'mock_client_id',
            'clientSecret' => 'mock_secret',
            'redirectUri' => 'mock_redirect_uri',
        ]);
    }

    public function tearDown(): void
    {
        m::close();
        parent::tearDown();
    }

    public function testAuthorizationUrl()
    {
        $url = $this->provider->getAuthorizationUrl();
        $uri = parse_url($url);
        parse_str($uri['query'], $query);

        $this->assertArrayHasKey('nonce', $query);
        $this->assertArrayHasKey('bail', $query);
        $this->assertArrayHasKey('code_challenge', $query);
        $this->assertArrayHasKey('code_challenge_method', $query);
        $this->assertArrayHasKey('state', $query);
        $this->assertArrayHasKey('scope', $query);
        $this->assertArrayHasKey('response_type', $query);
        $this->assertArrayHasKey('approval_prompt', $query);
        $this->assertArrayHasKey('redirect_uri', $query);
        $this->assertArrayHasKey('client_id', $query);
        $this->assertNotNull($this->provider->getState());
        $this->assertNotNull($this->provider->getNonce());
        $this->assertNotNull($this->provider->getCodeVerifier());
    }

    public function testGetBaseAccessTokenUrl()
    {
        $params = [];

        $url = $this->provider->getBaseAccessTokenUrl($params);
        $uri = parse_url($url);

        $this->assertEquals('/yconnect/v2/token', $uri['path']);
    }

    public function testGetAuthorizationUrl()
    {
        $url = $this->provider->getAuthorizationUrl();
        $uri = parse_url($url);

        $this->assertEquals('/yconnect/v2/authorization', $uri['path']);
    }

    public function testGetResourceOwnerDetails()
    {
        $id = uniqid();
        $name = uniqid();
        $given_name = uniqid();
        $given_name_kana = uniqid();
        $given_name_hani = uniqid();
        $family_name = uniqid();
        $family_name_kana = uniqid();
        $family_name_hani = uniqid();
        $gender = 'mock_gender';
        $birthdate = rand(1900, 2100);
        $nickname = uniqid();
        $picture = uniqid();
        $email = uniqid();
        $email_verified = 'true';
        $address = [
            "country" => uniqid(),
            "postal_code" => uniqid(),
            "region" => uniqid(),
            "locality" => uniqid(),
            "formatted" => uniqid()
        ];

        $token = m::mock('\League\OAuth2\Client\Token\AccessToken');
        $token->shouldReceive('getToken')->andReturn('mock_access_token');
        $token->shouldReceive('getValues')->andReturn(
            [
                'access_token' => 'mock_access_token',
                'token_type' => 'Bearer',
                'refresh_token' => 'mock_refresh_token',
                'expires_in' => 3600,
                'id_token' => 'mock_id_token'
            ]
        );

        $discoveryResponse = m::mock('Psr\Http\Message\ResponseInterface');
        $discoveryResponse->shouldReceive('getBody')->andReturn('{"authorization_endpoint":"mock_authorization_endpoint","token_endpoint":"token_endpoint_endpoint","userinfo_endpoint":"mock_userinfo_endpoint"}');
        $discoveryResponse->shouldReceive('getHeader')->andReturn(['content-type' => 'json']);
        $discoveryResponse->shouldReceive('getStatusCode')->andReturn(200);

        $userResponse = m::mock('Psr\Http\Message\ResponseInterface');
        $userResponse->shouldReceive('getBody')->andReturn('{"sub":"' . $id . '","name":"' . $name . '","given_name":"' . $given_name . '","given_name#ja-Kana-JP":"' . $given_name_kana . '","given_name#ja-Hani-JP":"' . $given_name_hani . '","family_name":"' . $family_name . '","family_name#ja-Kana-JP":"' . $family_name_kana . '","family_name#ja-Hani-JP":"' . $family_name_hani . '","gender":"' . $gender . '","zoneinfo":"Asia/Tokyo","locale":"ja-JP","birthdate":"' . $birthdate . '","nickname":"' . $nickname . '","picture":"' . $picture . '","email":"' . $email . '","email_verified":"' . $email_verified . '","address":{"country":"' . $address['country'] . '","postal_code":"' . $address['postal_code'] . '","region":"' . $address['region'] . '","locality":"' . $address['locality'] . '","formatted":"' . $address['formatted'] . '"}}');
        $userResponse->shouldReceive('getHeader')->andReturn(['content-type' => 'json']);
        $userResponse->shouldReceive('getStatusCode')->andReturn(200);

        $client = m::mock('GuzzleHttp\ClientInterface');
        $client->shouldReceive('send')
            ->times(2)
            ->andReturn($discoveryResponse, $userResponse);
        $this->provider->setHttpClient($client);

        $user = $this->provider->getResourceOwner($token);

        $this->assertEquals($id, $user->getId());
        $this->assertEquals($id, $user->toArray()['sub']);
        $this->assertEquals($name, $user->getName());
        $this->assertEquals($name, $user->toArray()['name']);
        $this->assertEquals($given_name, $user->getFirstName());
        $this->assertEquals($given_name, $user->toArray()['given_name']);
        $this->assertEquals($family_name, $user->getLastName());
        $this->assertEquals($family_name, $user->toArray()['family_name']);
        $this->assertEquals($nickname, $user->getNickname());
        $this->assertEquals($nickname, $user->toArray()['nickname']);
        $this->assertEquals($picture, $user->getPicture());
        $this->assertEquals($picture, $user->toArray()['picture']);
        $this->assertEquals($email, $user->getEmail());
        $this->assertEquals($email, $user->toArray()['email']);
        $this->assertIsArray($user->getAddress());
        $this->assertIsArray($user->toArray()['address']);

    }
}
