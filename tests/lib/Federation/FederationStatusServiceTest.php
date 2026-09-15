<?php

declare(strict_types=1);

namespace Test\SimpleSAML\Federation;

use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\authoauth2\Federation\FederationStatusService;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmEnum;

class FederationStatusServiceTest extends TestCase
{
    use FederationTestHelper;

    private const ENTITY_ID = 'https://rp.example.org/module.php/authoauth2';

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
     * @param array<string, mixed>|null $authSources
     * @return array<string, mixed>
     */
    private function buildStatus(array $overrides = [], ?array $authSources = []): array
    {
        [$keyConfig] = $this->createEntityKeyPair(SignatureAlgorithmEnum::RS256, 'rp-status');
        $config = array_merge([
            'entityId' => self::ENTITY_ID,
            'federationKeys' => [$keyConfig + ['keyId' => 'rp-key-1']],
            'trustAnchors' => [self::TA_ENTITY_ID],
            'lifetime' => 'PT1H',
            'cache' => false,
        ], $overrides);
        return (new FederationStatusService($config, $authSources))->getStatus();
    }

    public function testExposesConfiguredValues(): void
    {
        $status = $this->buildStatus([
            'scopes' => ['openid', 'email'],
            'trustMarks' => [['trust_mark_type' => 'https://example.org/tm', 'trust_mark' => 'jwt']],
        ]);

        $this->assertSame(self::ENTITY_ID, $status['entityId']);
        $this->assertSame([self::TA_ENTITY_ID], $status['trustAnchors']);
        $this->assertSame([self::TA_ENTITY_ID], $status['authorityHints'], 'hints default to anchors');
        $this->assertSame('PT1H', $status['lifetime']);
        $this->assertSame(['openid', 'email'], $status['scopes']);
        $this->assertSame('private_key_jwt', $status['tokenEndpointAuthMethod']);
        $this->assertSame(1, $status['trustMarkCount']);
        $this->assertFalse($status['cacheEnabled']);
    }

    public function testKeySummaryOmitsPrivateMaterial(): void
    {
        $status = $this->buildStatus();

        $this->assertCount(1, $status['keys']);
        $key = $status['keys'][0];
        $this->assertSame('RS256', $key['algorithm']);
        $this->assertSame('rp-key-1', $key['keyId']);
        $this->assertTrue($key['publicKeyExists']);
        foreach ($key as $value) {
            $this->assertStringNotContainsString('PRIVATE KEY', (string)$value);
        }
        // The privateKey path is never surfaced.
        $this->assertArrayNotHasKey('privateKey', $key);
    }

    public function testStatementSummaryReportsValidity(): void
    {
        $status = $this->buildStatus();

        $this->assertNull($status['statement']['error']);
        $this->assertNotNull($status['statement']['expiresAt']);
        $this->assertEqualsWithDelta(time() + 3600, $status['statement']['expiresAt'], 5);
        $this->assertEqualsWithDelta(3600, $status['statement']['secondsRemaining'], 5);
    }

    public function testStatementSummaryReportsBrokenConfig(): void
    {
        $status = $this->buildStatus(['federationKeys' => 'not-a-list']);

        $this->assertNotNull($status['statement']['error']);
        $this->assertNull($status['statement']['expiresAt']);
    }

    public function testAuthSourceScanFindsFederationSourcesOnly(): void
    {
        $status = $this->buildStatus(authSources: [
            'demo-op' => [
                'authoauth2:OpenIDConnect',
                'issuer' => self::OP_ENTITY_ID,
                'federation' => ['trustAnchors' => [self::TA_ENTITY_ID]],
            ],
            'plain-oidc' => [
                'authoauth2:OpenIDConnect',
                'issuer' => 'https://plain.example.org',
            ],
            'saml-sp' => ['saml20-sp'],
            'other-module-fed' => [
                'anothermodule:Something',
                'federation' => ['trustAnchors' => ['https://elsewhere.example.org']],
            ],
        ]);

        $this->assertCount(1, $status['authSources']);
        $source = $status['authSources'][0];
        $this->assertSame('demo-op', $source['name']);
        $this->assertSame(self::OP_ENTITY_ID, $source['issuer']);
        $this->assertTrue($source['hasOwnTrustAnchors']);
    }
}
