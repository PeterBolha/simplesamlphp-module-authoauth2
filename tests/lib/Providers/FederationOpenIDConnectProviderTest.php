<?php

declare(strict_types=1);

namespace Test\SimpleSAML\Providers;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Error\ConfigurationError;
use SimpleSAML\Module\authoauth2\Federation\OPMetadataResolver;
use SimpleSAML\Module\authoauth2\Providers\FederationOpenIDConnectProvider;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmEnum;
use SimpleSAML\OpenID\Federation\TrustChain;
use SimpleSAML\OpenID\ValueAbstracts\SignatureKeyPairBag;
use Test\SimpleSAML\Federation\FederationTestHelper;

class FederationOpenIDConnectProviderTest extends TestCase
{
    use FederationTestHelper;

    private const CLIENT_ID = 'test client id';
    private const RP_ENTITY_ID = 'https://rp.example.org/module.php/authoauth2';

    protected function setUp(): void
    {
        $this->initFedTmpDir();
    }

    protected function tearDown(): void
    {
        $this->removeFedTmpDir();
    }

    /**
     * Provider whose trust-chain resolution is stubbed with the given metadata
     * (and our own chain, when supplied), and whose HTTP client answers with
     * $httpResponses (jwks fetches etc.).
     *
     * @param array<string, mixed> $resolvedMetadata
     * @param array<string, mixed> $extraOptions
     */
    private function providerWithMetadata(
        array $resolvedMetadata,
        array $extraOptions = [],
        ?TrustChain $ownChain = null,
        Response ...$httpResponses,
    ): FederationOpenIDConnectProvider {
        $stack = HandlerStack::create(new MockHandler($httpResponses));
        $httpClient = new Client(['handler' => $stack]);

        $resolver = new class ($resolvedMetadata, $ownChain) extends OPMetadataResolver {
            /** @param array<string, mixed> $metadata */
            public function __construct(
                private readonly array $metadata,
                private readonly ?TrustChain $ownChain,
            ) {
            }

            public function resolveOPMetadata(string $opEntityId): array
            {
                return $this->metadata;
            }

            public function resolveChain(string $opEntityId): TrustChain
            {
                return $this->ownChain ?? parent::resolveChain($opEntityId);
            }
        };

        $provider = new FederationOpenIDConnectProvider(array_merge([
            'clientId' => self::CLIENT_ID,
            'clientSecret' => 'secret',
            'redirectUri' => 'https://rp.example.org/linkback',
            'opEntityId' => self::OP_ENTITY_ID,
            'federation' => ['trustAnchors' => [self::TA_ENTITY_ID], 'cache' => false],
        ], $extraOptions), ['httpClient' => $httpClient]);

        (function () use ($resolver): void {
            $this->metadataResolver = $resolver;
        })->call($provider);

        return $provider;
    }

    public function testEndpointsComeFromResolvedMetadata(): void
    {
        $provider = $this->providerWithMetadata($this->opProviderMetadata([
            'end_session_endpoint' => self::OP_ENTITY_ID . '/logout',
        ]));

        $this->assertSame(self::OP_ENTITY_ID . '/authorize', $provider->getBaseAuthorizationUrl());
        $this->assertSame(self::OP_ENTITY_ID . '/token', $provider->getBaseAccessTokenUrl([]));
        $this->assertSame(self::OP_ENTITY_ID . '/logout', $provider->getEndSessionEndpoint());
    }

    public function testNoDiscoveryUrlIsUsed(): void
    {
        // With no mocked responses at all, any accidental .well-known fetch
        // would throw; endpoint getters above prove discovery is not consulted.
        $provider = $this->providerWithMetadata($this->opProviderMetadata());
        $this->assertSame(self::OP_ENTITY_ID . '/token', $provider->getBaseAccessTokenUrl([]));
    }

    public function testIdTokenVerifiedAgainstInlineJwks(): void
    {
        [$opKeyConfig, $opKeys] = $this->createEntityKeyPair(SignatureAlgorithmEnum::RS256, 'op');
        $idToken = $this->signIdToken($opKeyConfig['privateKey'], $this->keyId($opKeys), [
            'aud' => self::CLIENT_ID, 'iss' => self::OP_ENTITY_ID]);

        $provider = $this->providerWithMetadata($this->opProviderMetadata([
            'jwks' => $this->publicJwksArray($opKeys),
        ]));

        $provider->verifyIdToken($idToken);
        $this->assertTrue(true); // no exception means signature + aud + iss verified
    }

    public function testIdTokenWithWrongIssuerRejected(): void
    {
        [$opKeyConfig, $opKeys] = $this->createEntityKeyPair(SignatureAlgorithmEnum::RS256, 'op');
        $idToken = $this->signIdToken($opKeyConfig['privateKey'], $this->keyId($opKeys), [
            'aud' => self::CLIENT_ID, 'iss' => 'https://evil.example.org']);

        $provider = $this->providerWithMetadata($this->opProviderMetadata([
            'jwks' => $this->publicJwksArray($opKeys),
        ]));

        $this->expectException(IdentityProviderException::class);
        $this->expectExceptionMessage('incorrect issuer');
        $provider->verifyIdToken($idToken);
    }

    public function testIdTokenWithWrongAudienceRejected(): void
    {
        [$opKeyConfig, $opKeys] = $this->createEntityKeyPair(SignatureAlgorithmEnum::RS256, 'op');
        $idToken = $this->signIdToken($opKeyConfig['privateKey'], $this->keyId($opKeys), [
            'aud' => 'someone else', 'iss' => self::OP_ENTITY_ID]);

        $provider = $this->providerWithMetadata($this->opProviderMetadata([
            'jwks' => $this->publicJwksArray($opKeys),
        ]));

        $this->expectException(IdentityProviderException::class);
        $this->expectExceptionMessage('incorrect audience');
        $provider->verifyIdToken($idToken);
    }

    public function testSigningKeysFetchedFromResolvedJwksUriWhenNoInlineJwks(): void
    {
        [$opKeyConfig, $opKeys] = $this->createEntityKeyPair(SignatureAlgorithmEnum::RS256, 'op');
        $idToken = $this->signIdToken($opKeyConfig['privateKey'], $this->keyId($opKeys), [
            'aud' => self::CLIENT_ID, 'iss' => self::OP_ENTITY_ID]);

        $provider = $this->providerWithMetadata(
            $this->opProviderMetadata(), // jwks_uri only
            [],
            null,
            new Response(
                200,
                ['Content-Type' => 'application/json'],
                json_encode($this->publicJwksArray($opKeys)),
            ),
        );

        $provider->verifyIdToken($idToken);
        $this->assertTrue(true);
    }

    public function testResolvedIssuerMismatchRejected(): void
    {
        $provider = $this->providerWithMetadata($this->opProviderMetadata([
            'issuer' => 'https://someone-else.example.org',
        ]));

        $this->expectException(IdentityProviderException::class);
        $this->expectExceptionMessage('does not match the OP entity ID');
        $provider->getBaseAuthorizationUrl();
    }

    public function testMissingEndpointRejected(): void
    {
        $metadata = $this->opProviderMetadata();
        unset($metadata['token_endpoint']);
        $provider = $this->providerWithMetadata($metadata);

        $this->expectException(IdentityProviderException::class);
        $this->expectExceptionMessage('missing a usable https token_endpoint');
        $provider->getBaseAccessTokenUrl([]);
    }

    public function testMissingJwksAndJwksUriRejected(): void
    {
        $metadata = $this->opProviderMetadata();
        unset($metadata['jwks_uri']);
        $provider = $this->providerWithMetadata($metadata);

        $this->expectException(IdentityProviderException::class);
        $this->expectExceptionMessage('neither inline jwks nor a usable https jwks_uri');
        $provider->verifyIdToken('whatever');
    }

    public function testMissingFederationOptionRejected(): void
    {
        $this->expectException(ConfigurationError::class);
        new FederationOpenIDConnectProvider([
            'clientId' => self::CLIENT_ID,
            'clientSecret' => 'secret',
            'redirectUri' => 'https://rp.example.org/linkback',
            'opEntityId' => self::OP_ENTITY_ID,
        ]);
    }

    public function testMissingOPIdentifierRejected(): void
    {
        $this->expectException(ConfigurationError::class);
        new FederationOpenIDConnectProvider([
            'clientId' => self::CLIENT_ID,
            'clientSecret' => 'secret',
            'redirectUri' => 'https://rp.example.org/linkback',
            'federation' => ['trustAnchors' => [self::TA_ENTITY_ID]],
        ]);
    }

    /**
     * RP federation identity: our entity ID + an RS256 key pair (the demo OP
     * accepts RS256 for request objects and client assertions).
     *
     * @return array{0: array<string, mixed>, 1: array{0: array<string, string>, 1: SignatureKeyPairBag}}
     */
    private function rpIdentity(): array
    {
        [$keyConfig, $keys] = $this->createEntityKeyPair(SignatureAlgorithmEnum::RS256, 'rp');
        return [
            ['entityId' => self::RP_ENTITY_ID, 'federationKeys' => [$keyConfig]],
            [$keyConfig, $keys],
        ];
    }

    /**
     * A provider configured for automatic registration: RP identity in the
     * source's federation block (no module config in tests), OP metadata and
     * our own trust chain stubbed.
     *
     * @return array{0: FederationOpenIDConnectProvider, 1: array{0: array<string, string>, 1: SignatureKeyPairBag}}
     */
    private function automaticRegistrationProvider(): array
    {
        [$rpIdentity, $rpKeys] = $this->rpIdentity();
        [$opKeyConfig, $opKeys] = $this->createEntityKeyPair(SignatureAlgorithmEnum::RS256, 'op-auto');
        $ownChain = $this->ownTrustChain();

        $provider = $this->providerWithMetadata(
            $this->opProviderMetadata(['jwks' => $this->publicJwksArray($opKeys)]),
            // clientId null (§12.1): exercises the provider deriving client_id
            // from the RP entityID instead of an explicit option.
            [
                'clientId' => null,
                'federation' => ['trustAnchors' => [self::TA_ENTITY_ID], 'cache' => false] + $rpIdentity,
            ],
            $ownChain,
        );
        return [$provider, $rpKeys, [$opKeyConfig, $opKeys]];
    }

    /**
     * Leaf -> (subordinate) -> TA chain about the RP, shaped for
     * TrustChain::jsonSerialize() (leaf first, trust anchor last).
     */
    private function ownTrustChain(): TrustChain
    {
        [$rpKeyConfig, $rpKeys] = $this->createEntityKeyPair(SignatureAlgorithmEnum::RS256, 'rp-chain');
        [, $taKeys] = $this->createEntityKeyPair(SignatureAlgorithmEnum::ES512, 'ta-chain');
        $rpJwks = $this->publicJwksArray($rpKeys);
        $taJwks = $this->publicJwksArray($taKeys);

        $leaf = $this->makeStatement($rpKeys, $this->leafConfigurationPayload(self::RP_ENTITY_ID, $rpJwks));
        $subordinate = $this->makeStatement($taKeys, $this->subordinatePayload(self::RP_ENTITY_ID, $rpJwks));
        $ta = $this->makeStatement($taKeys, $this->taConfigurationPayload($taJwks));

        return $this->federation()->trustChainFactory()->fromStatements($leaf, $subordinate, $ta);
    }

    /**
     * Decode a compact JWS into its header + payload, no signature check (the
     * signature itself is verified against our published key in a dedicated
     * test).
     *
     * @return array{0: array<string, mixed>, 1: array<string, mixed>}
     */
    private function decodeJws(string $token): array
    {
        $b64 = static fn(string $part): string => base64_decode(strtr($part, '-_', '+/'));
        [$header, $payload] = explode('.', $token);
        return [
            json_decode($b64($header), true),
            json_decode($b64($payload), true),
        ];
    }

    public function testAutomaticRegistrationUsesEntityIdAsClientIdAndDropsSecret(): void
    {
        [$provider] = $this->automaticRegistrationProvider();

        $this->assertTrue($provider->isAutomaticRegistrationEnabled());
        $this->assertTrue($provider->requiresPostAuthorizationRequest());
        $this->assertSame(self::RP_ENTITY_ID, (function () {
            return $this->clientId;
        })->call($provider));
        // No secret at all — league omits the null from the token request body.
        $this->assertNull((function () {
            return $this->clientSecret;
        })->call($provider));
    }

    public function testAutomaticRegistrationDisabledWithoutRpIdentity(): void
    {
        $provider = $this->providerWithMetadata($this->opProviderMetadata());
        $this->assertFalse($provider->isAutomaticRegistrationEnabled());
        $this->assertFalse($provider->requiresPostAuthorizationRequest());
    }

    public function testRequestObjectCarriesMandatoryClaims(): void
    {
        [$provider] = $this->automaticRegistrationProvider();

        $data = $provider->getAuthorizationFormData([
            'state' => 'authoauth2|42',
            'nonce' => 'n-123',
            'scope' => 'openid profile',
        ]);
        [, $payload] = $this->decodeJws($data['fields']['request']);

        $this->assertSame(self::RP_ENTITY_ID, $payload['iss']);
        $this->assertSame(self::RP_ENTITY_ID, $payload['client_id']);
        $this->assertSame(self::OP_ENTITY_ID, $payload['aud']);
        $this->assertArrayNotHasKey('sub', $payload, '§12.1.1.1: request objects must not carry sub');
        $this->assertNotEmpty($payload['jti']);
        $this->assertEqualsWithDelta(time() + 300, $payload['exp'], 5);
        $this->assertSame('authoauth2|42', $payload['state']);
        $this->assertSame('n-123', $payload['nonce']);
        $this->assertSame('openid profile', $payload['scope']);
        $this->assertSame('code', $payload['response_type']);
        $this->assertSame('https://rp.example.org/linkback', $payload['redirect_uri']);

        // Front-channel form: POST target + the minimal routing params, with
        // everything else (nonce, state, …) only inside the signed request.
        $this->assertSame(self::OP_ENTITY_ID . '/authorize', $data['url']);
        $this->assertSame(self::RP_ENTITY_ID, $data['fields']['client_id']);
        $this->assertSame('code', $data['fields']['response_type']);
        $this->assertArrayNotHasKey('nonce', $data['fields']);
        $this->assertArrayNotHasKey('state', $data['fields']);
    }

    public function testRequestObjectHeaderCarriesKidAndOwnTrustChain(): void
    {
        [$provider, $rpKeys] = $this->automaticRegistrationProvider();

        $data = $provider->getAuthorizationFormData(['state' => 's']);
        [$header] = $this->decodeJws($data['fields']['request']);

        $this->assertSame($this->keyId($rpKeys[1]), $header['kid']);
        $this->assertIsArray($header['trust_chain']);
        $this->assertCount(3, $header['trust_chain'], 'leaf, subordinate, TA');
        foreach ($header['trust_chain'] as $statement) {
            $this->assertIsString($statement);
            $this->assertSame(3, count(explode('.', $statement)), 'compact JWS');
        }
        // Leaf first: its subject is us.
        [, $leafPayload] = $this->decodeJws($header['trust_chain'][0]);
        $this->assertSame(self::RP_ENTITY_ID, $leafPayload['sub']);
    }

    public function testRequestObjectSignatureVerifiesAgainstRpFederationKey(): void
    {
        [$provider, $rpKeys] = $this->automaticRegistrationProvider();

        $data = $provider->getAuthorizationFormData(['state' => 's']);
        $jwks = $this->publicJwksArray($rpKeys[1]);
        JWT::$leeway = 5;
        try {
            $claims = JWT::decode($data['fields']['request'], $this->jwkObjects($jwks));
            $this->assertSame(self::RP_ENTITY_ID, $claims->iss);
        } finally {
            JWT::$leeway = 0;
        }
    }

    public function testClientAssertionClaimsAndSignature(): void
    {
        [$provider, $rpKeys] = $this->automaticRegistrationProvider();

        $assertion = (function () {
            return $this->buildClientAssertion();
        })->call($provider);
        [$header, $payload] = $this->decodeJws($assertion);

        $this->assertSame($this->keyId($rpKeys[1]), $header['kid']);
        $this->assertSame(self::RP_ENTITY_ID, $payload['iss']);
        $this->assertSame(self::RP_ENTITY_ID, $payload['sub']);
        $this->assertSame(self::OP_ENTITY_ID, $payload['aud']);
        $this->assertNotEmpty($payload['jti']);
        $this->assertEqualsWithDelta(time() + 300, $payload['exp'], 5);

        JWT::$leeway = 5;
        try {
            JWT::decode($assertion, $this->jwkObjects($this->publicJwksArray($rpKeys[1])));
        } finally {
            JWT::$leeway = 0;
        }
        $this->assertTrue(true);
    }

    public function testTokenRequestAuthenticatesWithClientAssertionNotSecret(): void
    {
        [$provider, , [$opKeyConfig, $opKeys]] = $this->automaticRegistrationProvider();

        $idToken = $this->signIdToken($opKeyConfig['privateKey'], $this->keyId($opKeys), [
            'aud' => self::RP_ENTITY_ID, 'iss' => self::OP_ENTITY_ID,
        ]);

        $captured = [];
        $stack = HandlerStack::create(new MockHandler([
            $this->jsonResponse([
                'access_token' => 'at', 'token_type' => 'Bearer', 'expires_in' => 3600,
                'id_token' => $idToken,
            ]),
        ]));
        $stack->push(\GuzzleHttp\Middleware::history($captured));
        $provider->setHttpClient(new Client(['handler' => $stack]));

        $provider->getAccessToken('authorization_code', ['code' => 'the-code']);

        $this->assertCount(1, $captured);
        $this->assertSame(self::OP_ENTITY_ID . '/token', (string)$captured[0]['request']->getUri());
        parse_str((string)$captured[0]['request']->getBody(), $body);
        $this->assertSame('urn:ietf:params:oauth:client-assertion-type:jwt-bearer', $body['client_assertion_type']);
        $this->assertSame(self::RP_ENTITY_ID, $body['client_id']);
        $this->assertSame('the-code', $body['code']);
        $this->assertArrayNotHasKey('client_secret', $body, 'automatic registration has no secret to send');
        [, $payload] = $this->decodeJws($body['client_assertion']);
        $this->assertSame(self::OP_ENTITY_ID, $payload['aud']);
        $this->assertSame(self::RP_ENTITY_ID, $payload['iss']);
    }

    private function keyId(SignatureKeyPairBag $keys): string
    {
        return $keys->getFirstOrFail()->getKeyPair()->getKeyId();
    }

    /**
     * @return array<string, mixed>
     */
    private function publicJwksArray(SignatureKeyPairBag $keys): array
    {
        return $this->federation()->jwksDecoratorFactory()->fromJwkDecorators(
            ...$keys->getAllPublicKeys(),
        )->jsonSerialize();
    }

    /**
     * kid-indexed firebase Key objects for JWT::decode signature verification.
     *
     * @param array<string, mixed> $jwks
     * @return array<string, \Firebase\JWT\Key>
     */
    private function jwkObjects(array $jwks): array
    {
        return JWK::parseKeySet($jwks);
    }

    /**
     * RS256-signed JWT with the given claims, for id_token verification tests.
     *
     * @param array<string, mixed> $claims
     */
    private function signIdToken(string $privateKeyPath, string $keyId, array $claims): string
    {
        $key = openssl_pkey_get_private((string)file_get_contents($privateKeyPath));
        $this->assertNotFalse($key);

        return JWT::encode(
            array_merge(['iat' => time(), 'sub' => 'user-1'], $claims),
            $key,
            'RS256',
            $keyId,
        );
    }
}
