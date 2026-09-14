<?php

declare(strict_types=1);

namespace Test\SimpleSAML\Providers;

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
use SimpleSAML\OpenID\ValueAbstracts\SignatureKeyPairBag;
use Test\SimpleSAML\Federation\FederationTestHelper;

class FederationOpenIDConnectProviderTest extends TestCase
{
    use FederationTestHelper;

    private const CLIENT_ID = 'test client id';

    protected function setUp(): void
    {
        $this->initFedTmpDir();
    }

    protected function tearDown(): void
    {
        $this->removeFedTmpDir();
    }

    /**
     * Provider whose trust-chain resolution is stubbed with the given metadata,
     * and whose HTTP client answers with $httpResponses (jwks fetches etc.).
     *
     * @param array<string, mixed> $resolvedMetadata
     * @param array<string, mixed> $extraOptions
     */
    private function providerWithMetadata(
        array $resolvedMetadata,
        array $extraOptions = [],
        Response ...$httpResponses,
    ): FederationOpenIDConnectProvider {
        $stack = HandlerStack::create(new MockHandler($httpResponses));
        $httpClient = new Client(['handler' => $stack]);

        $resolver = new class ($resolvedMetadata) extends OPMetadataResolver {
            /** @param array<string, mixed> $metadata */
            public function __construct(private readonly array $metadata)
            {
            }

            public function resolveOPMetadata(string $opEntityId): array
            {
                return $this->metadata;
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
