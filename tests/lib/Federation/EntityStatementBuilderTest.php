<?php

declare(strict_types=1);

namespace Test\SimpleSAML\Module\authoauth2\Federation;

use FilesystemIterator;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SimpleSAML\Error\ConfigurationError;
use SimpleSAML\Module\authoauth2\Federation\EntityStatementBuilder;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmBag;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmEnum;
use SimpleSAML\OpenID\Federation;
use SimpleSAML\OpenID\SupportedAlgorithms;
use PHPUnit\Framework\TestCase;

class EntityStatementBuilderTest extends TestCase
{
    private const ENTITY_ID = 'https://ssp.example.org/module.php/authoauth2';
    private const REDIRECT_URI = 'https://ssp.example.org/module.php/authoauth2/linkback';
    private const TRUST_ANCHOR = 'https://oidfed-ta-demo.incubator.geant.org';

    private string $tmpDir;

    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir() . '/authoauth2-fed-test-' . bin2hex(random_bytes(6));
        mkdir($this->tmpDir, 0o700, true);
    }

    protected function tearDown(): void
    {
        $this->removeDir($this->tmpDir);
    }

    /**
     * @param array<string, mixed> $overrides
     * @return array<string, mixed>
     */
    private function config(array $overrides = []): array
    {
        return array_merge([
            'entityId' => self::ENTITY_ID,
            'federationKeys' => [$this->generateKeyPair('RS256')],
            'trustAnchors' => [self::TRUST_ANCHOR],
            'cache' => false,
        ], $overrides);
    }

    /**
     * Generate a key pair and return the config entry pointing at it.
     *
     * @return array<string, string>
     */
    private function generateKeyPair(string $algorithm): array
    {
        $details = match ($algorithm) {
            'ES256' => ['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1'],
            'ES512' => ['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'secp521r1'],
            default => ['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048],
        };

        $key = openssl_pkey_new($details);
        $this->assertNotFalse($key);

        openssl_pkey_export($key, $privatePem);
        $publicDetail = openssl_pkey_get_details($key);
        $this->assertNotFalse($publicDetail);

        $suffix = str_replace('-', '', $algorithm) . '-' . bin2hex(random_bytes(4));
        $privatePath = $this->tmpDir . "/fed-$suffix.pem";
        $publicPath = $this->tmpDir . "/fed-$suffix.pub.pem";
        file_put_contents($privatePath, $privatePem);
        file_put_contents($publicPath, $publicDetail['key']);

        return ['privateKey' => $privatePath, 'publicKey' => $publicPath, 'algorithm' => $algorithm];
    }

    private function parseToken(string $token): \SimpleSAML\OpenID\Federation\EntityStatement
    {
        $federation = new Federation(new SupportedAlgorithms(new SignatureAlgorithmBag(
            SignatureAlgorithmEnum::RS256,
            SignatureAlgorithmEnum::ES256,
            SignatureAlgorithmEnum::ES512,
        )));
        return $federation->entityStatementFactory()->fromToken($token);
    }

    public function testBuildProducesWellFormedSelfSignedStatement(): void
    {
        $builder = new EntityStatementBuilder($this->config(), self::REDIRECT_URI, $this->tmpDir . '/cache');
        $statement = $builder->build();

        $this->assertTrue($statement->isConfiguration(), 'iss must equal sub for an entity configuration');
        $this->assertSame(self::ENTITY_ID, $statement->getIssuer());
        $this->assertSame(self::ENTITY_ID, $statement->getSubject());
        $this->assertSame('RS256', $statement->getAlgorithm());

        $now = time();
        $this->assertIsInt($statement->getIssuedAt());
        $this->assertEqualsWithDelta($now, $statement->getIssuedAt(), 5);
        $this->assertEqualsWithDelta($now + 86400, $statement->getExpirationTime(), 5);

        $payload = $statement->getPayload();
        $this->assertNotEmpty($payload['jti']);
        $this->assertSame([self::TRUST_ANCHOR], $payload['authority_hints']);

        [$headerPart] = explode('.', $statement->getToken());
        $header = json_decode(base64_decode(strtr($headerPart, '-_', '+/')), true);
        $this->assertSame('entity-statement+jwt', $header['typ']);
        $this->assertSame($statement->getKeyId(), $header['kid']);
    }

    public function testSignatureVerifiesAgainstOwnPublishedJwks(): void
    {
        $builder = new EntityStatementBuilder($this->config(), self::REDIRECT_URI, $this->tmpDir . '/cache');
        $statement = $builder->build();

        $published = $this->parseToken($statement->getToken());
        $jwks = $published->getPayload()['jwks'];
        $this->assertCount(1, $jwks['keys']);
        // Public JWK only: no private material may leak into the published JWKS.
        foreach ($jwks['keys'] as $jwk) {
            $this->assertArrayNotHasKey('d', $jwk);
        }

        // Must not throw.
        $published->verifyWithKeySet($jwks);
    }

    public function testRpMetadataBlockMatchesModuleDefaults(): void
    {
        $builder = new EntityStatementBuilder($this->config(), self::REDIRECT_URI, $this->tmpDir . '/cache');
        $metadata = $builder->build()->getMetadata()['openid_relying_party'] ?? null;

        $this->assertIsArray($metadata);
        $this->assertSame([self::REDIRECT_URI], $metadata['redirect_uris']);
        $this->assertSame(['authorization_code'], $metadata['grant_types']);
        $this->assertSame(['code'], $metadata['response_types']);
        $this->assertSame('web', $metadata['application_type']);
        $this->assertSame('openid profile', $metadata['scope']);
        $this->assertSame(['query', 'form_post'], $metadata['response_modes_supported']);
        $this->assertSame('private_key_jwt', $metadata['token_endpoint_auth_method']);
        $this->assertSame(['RS256'], $metadata['id_token_signing_alg_values_supported']);

        $this->assertIsArray($metadata['jwks']);
        $this->assertCount(1, $metadata['jwks']['keys'], 'federation public keys double as client keys');
        foreach ($metadata['jwks']['keys'] as $jwk) {
            $this->assertArrayNotHasKey('d', $jwk);
        }
    }

    public function testRpMetadataOverridesAndPassthrough(): void
    {
        $config = $this->config([
            'additionalRpMetadata' => [
                'client_name' => 'Test RP',
                'jwks' => ['keys' => []],
                'token_endpoint_auth_method' => 'client_secret_basic',
            ],
            'additionalClaims' => ['organization_name' => 'Test Org'],
        ]);
        $builder = new EntityStatementBuilder($config, self::REDIRECT_URI, $this->tmpDir . '/cache');
        $statement = $builder->build();

        $metadata = $statement->getMetadata()['openid_relying_party'];
        $this->assertSame('Test RP', $metadata['client_name']);
        $this->assertSame(['keys' => []], $metadata['jwks']);
        $this->assertSame('client_secret_basic', $metadata['token_endpoint_auth_method']);
        $this->assertSame('Test Org', $statement->getPayload()['organization_name']);
    }

    public function testEcKeySigningAndMultipleKeyPublication(): void
    {
        $config = $this->config([
            'federationKeys' => [
                $this->generateKeyPair('ES512'),
                $this->generateKeyPair('RS256'),
            ],
        ]);
        $builder = new EntityStatementBuilder($config, self::REDIRECT_URI, $this->tmpDir . '/cache');
        $statement = $builder->build();

        $this->assertSame('ES512', $statement->getAlgorithm(), 'first key must sign');

        $published = $this->parseToken($statement->getToken());
        $jwks = $published->getPayload()['jwks'];
        $this->assertCount(2, $jwks['keys'], 'all public keys must be published for rollover');

        $algs = array_column($jwks['keys'], 'alg');
        $this->assertContains('ES512', $algs);
        $this->assertContains('RS256', $algs);

        // The statement is signed by the EC key; the mixed JWKS must still verify it.
        $published->verifyWithKeySet($jwks);
    }

    public function testTrustMarksAndExplicitAuthorityHints(): void
    {
        $marks = [['trust_mark_type' => 'https://example.org/tm', 'trust_mark' => 'some.jwt.token']];
        $config = $this->config([
            'authorityHints' => ['https://intermediate.example.org'],
            'trustMarks' => [$marks[0], ['invalid' => true]],
        ]);
        $builder = new EntityStatementBuilder($config, self::REDIRECT_URI, $this->tmpDir . '/cache');
        $payload = $builder->build()->getPayload();

        $this->assertSame(['https://intermediate.example.org'], $payload['authority_hints']);
        $this->assertSame([$marks[0]], $payload['trust_marks'], 'invalid trust mark entries must be dropped');
    }

    public function testSerializedStatementIsCachedUntilNearExpiry(): void
    {
        $cacheDir = $this->tmpDir . '/cache';
        $config = $this->config(['lifetime' => 'PT1H', 'cache' => true]);
        $builder = new EntityStatementBuilder($config, self::REDIRECT_URI, $cacheDir);

        $first = $builder->getSerializedStatement();
        $this->assertArrayHasKey('token', $first);
        $this->assertGreaterThan(0, $first['expiresIn']);
        // 1h lifetime minus the 60s safety margin.
        $this->assertEqualsWithDelta(3600 - 60, $first['expiresIn'], 5);

        $second = (new EntityStatementBuilder($config, self::REDIRECT_URI, $cacheDir))->getSerializedStatement();
        $this->assertSame($first['token'], $second['token'], 'second call must be served from cache');

        // A different entityId is a different cache entry.
        $otherConfig = $this->config(['entityId' => 'https://other.example.org/module.php/authoauth2']);
        $other = (new EntityStatementBuilder($otherConfig, self::REDIRECT_URI, $cacheDir))->getSerializedStatement();
        $this->assertNotSame($first['token'], $other['token']);

        // Cache disabled: always rebuilt.
        $noCacheConfig = $this->config(['lifetime' => 'PT1H', 'cache' => false]);
        $a = (new EntityStatementBuilder($noCacheConfig, self::REDIRECT_URI, $cacheDir))->getSerializedStatement();
        $b = (new EntityStatementBuilder($noCacheConfig, self::REDIRECT_URI, $cacheDir))->getSerializedStatement();
        $this->assertNotSame($a['token'], $b['token'], 'jti must differ when caching is off');
    }

    public function testMissingEntityIdThrows(): void
    {
        $config = $this->config();
        unset($config['entityId']);
        $this->expectException(ConfigurationError::class);
        new EntityStatementBuilder($config, self::REDIRECT_URI, $this->tmpDir . '/cache');
    }

    public function testMissingKeysThrows(): void
    {
        $config = $this->config();
        unset($config['federationKeys']);
        $this->expectException(ConfigurationError::class);
        new EntityStatementBuilder($config, self::REDIRECT_URI, $this->tmpDir . '/cache');
    }

    public function testUnknownAlgorithmThrows(): void
    {
        $config = $this->config([
            'federationKeys' => [
                ['privateKey' => '/nope', 'publicKey' => '/nope', 'algorithm' => 'HS256'],
            ],
        ]);
        $this->expectException(ConfigurationError::class);
        new EntityStatementBuilder($config, self::REDIRECT_URI, $this->tmpDir . '/cache');
    }

    public function testRedirectUriRequiredWithoutDefault(): void
    {
        $config = $this->config();
        $this->expectException(ConfigurationError::class);
        new EntityStatementBuilder($config, null, $this->tmpDir . '/cache');
    }

    private function removeDir(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }
        $items = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::CHILD_FIRST,
        );
        foreach ($items as $item) {
            $item->isDir() ? rmdir($item->getPathname()) : unlink($item->getPathname());
        }
        rmdir($dir);
    }
}
