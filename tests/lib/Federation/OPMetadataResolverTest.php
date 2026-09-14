<?php

declare(strict_types=1);

namespace Test\SimpleSAML\Module\authoauth2\Federation;

use GuzzleHttp\Client;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Error\ConfigurationError;
use SimpleSAML\Module\authoauth2\Federation\OPMetadataResolver;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmEnum;
use SimpleSAML\OpenID\ValueAbstracts\SignatureKeyPairBag;
use Test\SimpleSAML\Federation\FederationTestHelper;

class OPMetadataResolverTest extends TestCase
{
    use FederationTestHelper;

    protected function setUp(): void
    {
        $this->initFedTmpDir();
    }

    protected function tearDown(): void
    {
        $this->removeFedTmpDir();
    }

    /**
     * @param array<string, mixed> $overrides
     * @return array<string, mixed>
     */
    private function config(array $overrides = []): array
    {
        return array_merge([
            'trustAnchors' => [self::TA_ENTITY_ID],
            'cache' => false,
        ], $overrides);
    }

    private function resolver(array $overrides = [], ?Client $client = null): OPMetadataResolver
    {
        return new OPMetadataResolver($this->config($overrides), $client ? ['httpClient' => $client] : []);
    }

    /**
     * @return array<string, mixed>
     */
    private function publicJwks(SignatureKeyPairBag $keys): array
    {
        return $this->federation()->jwksDecoratorFactory()->fromJwkDecorators(
            ...$keys->getAllPublicKeys(),
        )->jsonSerialize();
    }

    /**
     * A leaf -> TA-subordinate -> TA trust chain with generated keys, plus a
     * mock HTTP client answering the three fetches the resolver makes
     * (OP well-known, TA well-known, subordinate from the TA fetch endpoint).
     *
     * @param array<string, mixed>|null $opProviderMetadata metadata.openid_provider of the leaf
     * @param array<string, mixed>|null $subJwks            JWKS claim of the subordinate statement
     * @param array<string, mixed>      $subOverrides       extra subordinate payload claims
     */
    private function fixture(
        ?array $opProviderMetadata = [],
        ?array $subJwks = null,
        array $subOverrides = [],
        SignatureAlgorithmEnum $taAlgorithm = SignatureAlgorithmEnum::RS256,
    ): array {
        [, $opKeys] = $this->createEntityKeyPair(SignatureAlgorithmEnum::RS256, 'op');
        [, $taKeys] = $this->createEntityKeyPair($taAlgorithm, 'ta');

        $leafMetadata = $opProviderMetadata === null
            ? ['federation_entity' => ['homepage_uri' => self::OP_ENTITY_ID]]
            : ['openid_provider' => $opProviderMetadata ?: $this->opProviderMetadata()];

        $leaf = $this->makeStatement($opKeys, $this->leafConfigurationPayload(
            self::OP_ENTITY_ID,
            $this->publicJwks($opKeys),
            ['metadata' => $leafMetadata],
        ));
        $subordinate = $this->makeStatement($taKeys, $this->subordinatePayload(
            self::OP_ENTITY_ID,
            $subJwks ?? $this->publicJwks($opKeys),
            $subOverrides,
        ));
        $taConfig = $this->makeStatement($taKeys, $this->taConfigurationPayload($this->publicJwks($taKeys)));

        return [$leaf, $subordinate, $taConfig];
    }

    /**
     * @param array<int, \Psr\Http\Message\ResponseInterface> $responses
     */
    private function resolverFor(array $responses): OPMetadataResolver
    {
        return $this->resolver([], $this->mockFetchClient(...$responses));
    }

    public function testResolvesOPMetadataThroughTrustChain(): void
    {
        [$leaf, $subordinate, $taConfig] = $this->fixture();
        $resolver = $this->resolverFor([
            $this->statementResponse($leaf),
            $this->statementResponse($taConfig),
            $this->statementResponse($subordinate),
        ]);

        $metadata = $resolver->resolveOPMetadata(self::OP_ENTITY_ID);

        $this->assertSame(self::OP_ENTITY_ID, $metadata['issuer']);
        $this->assertSame(self::OP_ENTITY_ID . '/authorize', $metadata['authorization_endpoint']);
        $this->assertSame(self::OP_ENTITY_ID . '/token', $metadata['token_endpoint']);
        $this->assertSame(self::OP_ENTITY_ID . '/userinfo', $metadata['userinfo_endpoint']);
    }

    public function testResolvesChainWithEs512SignedTrustAnchor(): void
    {
        // The GÉANT demo TA signs with ES512; resolution must accept it.
        [$leaf, $subordinate, $taConfig] = $this->fixture(taAlgorithm: SignatureAlgorithmEnum::ES512);
        $resolver = $this->resolverFor([
            $this->statementResponse($leaf),
            $this->statementResponse($taConfig),
            $this->statementResponse($subordinate),
        ]);

        $chain = $resolver->resolveChain(self::OP_ENTITY_ID);

        $this->assertSame('ES512', $chain->getResolvedTrustAnchor()->getAlgorithm());
        $this->assertSame(self::OP_ENTITY_ID, $chain->getResolvedLeaf()->getSubject());
    }

    public function testMetadataPolicyFromTrustAnchorIsApplied(): void
    {
        $policy = ['openid_provider' => ['token_endpoint' => ['value' => 'https://pinned.example.org/token']]];
        [$leaf, $subordinate, $taConfig] = $this->fixture(subOverrides: ['metadata_policy' => $policy]);
        $resolver = $this->resolverFor([
            $this->statementResponse($leaf),
            $this->statementResponse($taConfig),
            $this->statementResponse($subordinate),
        ]);

        $metadata = $resolver->resolveOPMetadata(self::OP_ENTITY_ID);

        $this->assertSame('https://pinned.example.org/token', $metadata['token_endpoint']);
        $this->assertSame(self::OP_ENTITY_ID . '/authorize', $metadata['authorization_endpoint']);
    }

    public function testTamperedSubordinateStatementIsRejected(): void
    {
        // Subordinate carries different OP keys than the leaf publishes: chain
        // verification against the issuer's key material must fail.
        [, $otherKeys] = $this->createEntityKeyPair(SignatureAlgorithmEnum::RS256, 'other');
        [$leaf, $subordinate, $taConfig] = $this->fixture(subJwks: $this->publicJwks($otherKeys));
        $resolver = $this->resolverFor([
            $this->statementResponse($leaf),
            $this->statementResponse($taConfig),
            $this->statementResponse($subordinate),
        ]);

        // Assembly in simplesamlphp/openid verifies each configuration against
        // the subordinate's key set, so a tampered subordinate yields no chain.
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Could not resolve a trust chain');
        $resolver->resolveOPMetadata(self::OP_ENTITY_ID);
    }

    public function testUnreachableTrustAnchorFailsResolution(): void
    {
        [$leaf] = $this->fixture();
        $resolver = $this->resolverFor([
            $this->statementResponse($leaf),
            new Response(404, [], 'not found'),
        ]);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Could not resolve a trust chain');
        $resolver->resolveOPMetadata(self::OP_ENTITY_ID);
    }

    public function testResolvedLeafMustMatchRequestedOPEntityId(): void
    {
        // A hostile/compromised registration serving the OP's statement under a
        // different entity ID resolves to a chain whose leaf is about someone
        // else; the leaf subject must match the requested OP.
        [$leaf, $subordinate, $taConfig] = $this->fixture();
        $resolver = $this->resolverFor([
            $this->statementResponse($leaf),
            $this->statementResponse($taConfig),
            $this->statementResponse($subordinate),
        ]);

        // Failure may surface either during resolution (library rejects the
        // statement as not being about the requested entity) or at our leaf
        // check; both wrap into a RuntimeException naming the requested OP.
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('https://evil.example.org');
        $resolver->resolveChain('https://evil.example.org');
    }

    public function testOPWithoutOpenIDProviderMetadataFails(): void
    {
        [$leaf, $subordinate, $taConfig] = $this->fixture(opProviderMetadata: null);
        $resolver = $this->resolverFor([
            $this->statementResponse($leaf),
            $this->statementResponse($taConfig),
            $this->statementResponse($subordinate),
        ]);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('no openid_provider metadata');
        $resolver->resolveOPMetadata(self::OP_ENTITY_ID);
    }

    public function testEmptyTrustAnchorsRejected(): void
    {
        $this->expectException(ConfigurationError::class);
        new OPMetadataResolver(['trustAnchors' => []]);
    }

    public function testMissingTrustAnchorsRejected(): void
    {
        $this->expectException(ConfigurationError::class);
        new OPMetadataResolver([]);
    }
}
