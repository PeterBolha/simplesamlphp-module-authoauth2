<?php

declare(strict_types=1);

namespace Test\SimpleSAML\Federation;

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmBag;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmEnum;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Federation;
use SimpleSAML\OpenID\Federation\EntityStatement;
use SimpleSAML\OpenID\SupportedAlgorithms;
use SimpleSAML\OpenID\ValueAbstracts\Factories\SignatureKeyPairBagFactory;
use SimpleSAML\OpenID\ValueAbstracts\KeyPairFilenameConfig;
use SimpleSAML\OpenID\ValueAbstracts\SignatureKeyPairBag;
use SimpleSAML\OpenID\ValueAbstracts\SignatureKeyPairConfig;
use SimpleSAML\OpenID\ValueAbstracts\SignatureKeyPairConfigBag;

/**
 * Shared fixtures for federation tests: generated key pairs on disk and
 * hand-signed entity statements forming a leaf -> (subordinate) -> TA chain.
 */
trait FederationTestHelper
{
    protected const OP_ENTITY_ID = 'https://op.example.org';
    protected const TA_ENTITY_ID = 'https://ta.example.org';

    protected string $fedTmpDir;

    protected function initFedTmpDir(): void
    {
        $this->fedTmpDir = sys_get_temp_dir() . '/authoauth2-fed-resolver-test-' . bin2hex(random_bytes(6));
        mkdir($this->fedTmpDir, 0o700, true);
    }

    protected function removeFedTmpDir(): void
    {
        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($this->fedTmpDir, \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::CHILD_FIRST,
        );
        foreach ($iterator as $file) {
            $file->isDir() ? rmdir($file->getPathname()) : unlink($file->getPathname());
        }
        rmdir($this->fedTmpDir);
    }

    /**
     * @return array{0: array<string, string>, 1: SignatureKeyPairBag} config entry + loaded key pair bag
     */
    protected function createEntityKeyPair(SignatureAlgorithmEnum $algorithm, string $prefix): array
    {
        $details = match ($algorithm) {
            SignatureAlgorithmEnum::ES256 => ['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1'],
            SignatureAlgorithmEnum::ES512 => ['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'secp521r1'],
            default => ['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048],
        };

        $key = openssl_pkey_new($details);
        TestCase::assertNotFalse($key);
        openssl_pkey_export($key, $privatePem);
        $publicDetail = openssl_pkey_get_details($key);
        TestCase::assertNotFalse($publicDetail);

        $privatePath = $this->fedTmpDir . "/$prefix.pem";
        $publicPath = $this->fedTmpDir . "/$prefix.pub.pem";
        file_put_contents($privatePath, $privatePem);
        file_put_contents($publicPath, $publicDetail['key']);

        $bag = (new SignatureKeyPairBagFactory())->fromConfig(new SignatureKeyPairConfigBag(
            new SignatureKeyPairConfig($algorithm, new KeyPairFilenameConfig($privatePath, $publicPath)),
        ));

        return [['privateKey' => $privatePath, 'publicKey' => $publicPath, 'algorithm' => $algorithm->value], $bag];
    }

    protected function federation(): Federation
    {
        return new Federation(new SupportedAlgorithms(new SignatureAlgorithmBag(
            SignatureAlgorithmEnum::RS256,
            SignatureAlgorithmEnum::ES256,
            SignatureAlgorithmEnum::ES384,
            SignatureAlgorithmEnum::ES512,
        )));
    }

    /**
     * @param array<non-empty-string, mixed> $payload
     */
    protected function makeStatement(SignatureKeyPairBag $keys, array $payload): EntityStatement
    {
        $keyPair = $keys->getFirstOrFail();
        return $this->federation()->entityStatementFactory()->fromData(
            $keyPair->getKeyPair()->getPrivateKey(),
            $keyPair->getSignatureAlgorithm(),
            $payload,
            [ClaimsEnum::Kid->value => $keyPair->getKeyPair()->getKeyId()],
        );
    }

    /**
     * @param array<string, mixed> $jwks
     * @return array<non-empty-string, mixed>
     */
    protected function leafConfigurationPayload(string $entityId, array $jwks, array $overrides = []): array
    {
        return array_merge([
            ClaimsEnum::Iss->value => $entityId,
            ClaimsEnum::Sub->value => $entityId,
            ClaimsEnum::Iat->value => time(),
            ClaimsEnum::Exp->value => time() + 86400,
            ClaimsEnum::Jti->value => bin2hex(random_bytes(16)),
            ClaimsEnum::Jwks->value => $jwks,
            ClaimsEnum::AuthorityHints->value => [self::TA_ENTITY_ID],
        ], $overrides);
    }

    /**
     * @param array<string, mixed> $jwks
     * @return array<non-empty-string, mixed>
     */
    protected function taConfigurationPayload(array $jwks, array $overrides = []): array
    {
        return array_merge([
            ClaimsEnum::Iss->value => self::TA_ENTITY_ID,
            ClaimsEnum::Sub->value => self::TA_ENTITY_ID,
            ClaimsEnum::Iat->value => time(),
            ClaimsEnum::Exp->value => time() + 86400,
            ClaimsEnum::Jti->value => bin2hex(random_bytes(16)),
            ClaimsEnum::Jwks->value => $jwks,
            'metadata' => ['federation_entity' => [
                'federation_fetch_endpoint' => self::TA_ENTITY_ID . '/fetch',
            ]],
        ], $overrides);
    }

    /**
     * Subordinate statement about $subjectId, signed with the TA's key. The JWKS
     * claim is the SUBJECT's public keys — verification uses the subject's key
     * set, not the issuer's.
     *
     * @param array<string, mixed> $subjectJwks
     * @return array<non-empty-string, mixed>
     */
    protected function subordinatePayload(
        string $subjectId,
        array $subjectJwks,
        array $overrides = [],
    ): array {
        return array_merge([
            ClaimsEnum::Iss->value => self::TA_ENTITY_ID,
            ClaimsEnum::Sub->value => $subjectId,
            ClaimsEnum::Iat->value => time(),
            ClaimsEnum::Exp->value => time() + 86400,
            ClaimsEnum::Jti->value => bin2hex(random_bytes(16)),
            ClaimsEnum::Jwks->value => $subjectJwks,
        ], $overrides);
    }

    /**
     * Minimal openid_provider metadata, shaped like a real OP's.
     *
     * @return array<string, mixed>
     */
    protected function opProviderMetadata(array $overrides = []): array
    {
        return array_merge([
            'issuer' => self::OP_ENTITY_ID,
            'authorization_endpoint' => self::OP_ENTITY_ID . '/authorize',
            'token_endpoint' => self::OP_ENTITY_ID . '/token',
            'userinfo_endpoint' => self::OP_ENTITY_ID . '/userinfo',
            'jwks_uri' => self::OP_ENTITY_ID . '/jwks',
            'response_types_supported' => ['code'],
            'id_token_signing_alg_values_supported' => ['RS256'],
        ], $overrides);
    }

    protected function mockFetchClient(Response ...$responses): Client
    {
        $stack = HandlerStack::create(new MockHandler($responses));
        return new Client(['handler' => $stack]);
    }

    protected function statementResponse(EntityStatement $statement): Response
    {
        return new Response(200, ['Content-Type' => 'application/entity-statement+jwt'], $statement->getToken());
    }

    protected function jsonResponse(array $body, int $status = 200): Response
    {
        return new Response($status, ['Content-Type' => 'application/json'], json_encode($body));
    }
}
