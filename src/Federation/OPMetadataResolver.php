<?php

declare(strict_types=1);

namespace SimpleSAML\Module\authoauth2\Federation;

use GuzzleHttp\Client;
use SimpleSAML\Error\ConfigurationError;
use SimpleSAML\Logger;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmBag;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmEnum;
use SimpleSAML\OpenID\Codebooks\EntityTypesEnum;
use SimpleSAML\OpenID\Exceptions\TrustChainException;
use SimpleSAML\OpenID\Federation;
use SimpleSAML\OpenID\Federation\TrustChain;
use SimpleSAML\OpenID\SupportedAlgorithms;
use Symfony\Component\Cache\Adapter\FilesystemAdapter;
use Symfony\Component\Cache\Psr16Cache;

/**
 * Resolves the policy-applied openid_provider metadata of an OpenID Provider
 * reachable through one of the configured trust anchors (OpenID Federation
 * 1.0 §11.2: establish trust by resolving a Trust Chain to a configured Trust
 * Anchor, then use the Resolved Metadata in place of .well-known discovery).
 *
 * Every statement in the resolved chain is verified here (OpenID Federation
 * 1.0 §11.2, §10.3): each Entity Configuration against its own published JWKS
 * and each Subordinate Statement against the JWKS its issuer publishes in the
 * chain.
 *
 * @throws ConfigurationError Thrown by the constructor on unusable configuration.
 */
class OPMetadataResolver
{
    /**
     * Algorithms accepted when verifying federation statements. RS256 plus the
     * ES* family because Trust Anchors in the wild sign with EC keys (the GÉANT
     * demo TA uses ES512).
     */
    private const SUPPORTED_SIGNING_ALGORITHMS = [
        SignatureAlgorithmEnum::RS256,
        SignatureAlgorithmEnum::ES256,
        SignatureAlgorithmEnum::ES384,
        SignatureAlgorithmEnum::ES512,
    ];

    /** @var non-empty-list<non-empty-string> */
    private readonly array $trustAnchors;

    /** @var array<string, mixed> */
    private readonly array $options;

    private readonly bool $cacheEnabled;

    private readonly ?string $cacheDir;

    private ?Federation $federation = null;

    /**
     * @param array<string, mixed> $config the auth source's 'federation' config array:
     *                                     trustAnchors (required, list of Trust Anchor entity IDs),
     *                                     cache (bool, default true), cacheDir (string, optional override).
     * @param array<string, mixed> $options Provider-level passthrough, e.g. 'httpClient' => Guzzle client.
     */
    public function __construct(array $config, array $options = [])
    {
        $trustAnchors = $config['trustAnchors'] ?? null;
        if (!is_array($trustAnchors) || $trustAnchors === []) {
            throw new ConfigurationError('federation.trustAnchors must list at least one trust anchor entity ID');
        }
        $anchors = [];
        foreach ($trustAnchors as $anchor) {
            if (!is_string($anchor) || $anchor === '') {
                continue;
            }
            $anchors[] = $anchor;
        }
        if ($anchors === []) {
            throw new ConfigurationError('federation.trustAnchors contains no valid trust anchor entity IDs');
        }
        $this->trustAnchors = $anchors;
        $this->options = $options;
        $this->cacheEnabled = (bool)($config['cache'] ?? true);
        $this->cacheDir = isset($config['cacheDir']) && is_string($config['cacheDir'])
            ? $config['cacheDir']
            : null;
    }

    /**
     * Resolve and verify the trust chain for one OP, returning its resolved metadata.
     *
     * @return array<string, mixed> The openid_provider metadata after metadata policy
     *                              was applied (§11.2 — MUST NOT use metadata that
     *                              did not come from a verified Trust Chain).
     * @throws \RuntimeException If no trusted chain resolves or the OP publishes no
     *                           openid_provider metadata.
     */
    public function resolveOPMetadata(string $opEntityId): array
    {
        $chain = $this->resolveChain($opEntityId);

        $metadata = $chain->getResolvedMetadata(EntityTypesEnum::OpenIdProvider);
        if ($metadata === null) {
            throw new \RuntimeException(
                "Resolved trust chain for '$opEntityId' but it publishes no openid_provider metadata",
            );
        }

        Logger::debug("authoauth2: resolved federation metadata for OP $opEntityId"
            . ' via trust anchor(s): ' . implode(', ', $this->trustAnchors));
        return $metadata;
    }

    /**
     * Shortest verified trust chain for the OP, ending at one of our trust anchors.
     */
    public function resolveChain(string $opEntityId): TrustChain
    {
        if ($opEntityId === '') {
            throw new \RuntimeException('Cannot resolve a trust chain for an empty OP entity ID');
        }
        try {
            $chains = $this->federation()->trustChainResolver()->for($opEntityId, $this->trustAnchors);
        } catch (TrustChainException $e) {
            throw new \RuntimeException(
                "Could not resolve a trust chain for OP '$opEntityId' to any configured trust anchor:"
                . ' ' . $e->getMessage(),
                0,
                $e,
            );
        }

        $chain = $chains->getShortest();
        $leaf = $chain->getResolvedLeaf();
        if ($leaf->getSubject() !== $opEntityId || $leaf->getIssuer() !== $opEntityId) {
            throw new \RuntimeException(
                "Resolved trust chain leaf is not the expected OP entity configuration for '$opEntityId'",
            );
        }
        $this->verifyChain($chain, $opEntityId);
        return $chain;
    }

    /**
     * Verify every signature in the chain (§11.2: trust is only established
     * through verified statements):
     *  - each Entity Configuration with its own published JWKS,
     *  - each Subordinate Statement with the JWKS of its issuer, taken from the
     *    nearest following statement about that issuer (its Entity
     *    Configuration, or a Subordinate Statement carrying its JWKS).
     *
     * @throws \RuntimeException On any failed verification.
     */
    private function verifyChain(TrustChain $chain, string $opEntityId): void
    {
        $entities = array_values($chain->getEntities());

        try {
            $chain->validateExpirationTime();
        } catch (\Exception $e) {
            throw new \RuntimeException(
                "Trust chain for OP '$opEntityId' contains expired statements: " . $e->getMessage(),
                0,
                $e,
            );
        }

        foreach ($entities as $index => $statement) {
            try {
                if ($statement->isConfiguration()) {
                    $statement->verifyWithKeySet();
                    continue;
                }
                $issuerKeys = $this->entityKeys($entities, $index, $statement->getIssuer());
                $statement->verifyWithKeySet($issuerKeys);
            } catch (\Exception $e) {
                throw new \RuntimeException(
                    "Trust chain verification failed for OP '$opEntityId' at statement " . ($index + 1)
                    . " (issuer {$statement->getIssuer()}): " . $e->getMessage(),
                    0,
                    $e,
                );
            }
        }
    }

    /**
     * JWKS of the given entity from the first statement at or after $afterIndex
     * whose subject is that entity.
     *
     * @param \SimpleSAML\OpenID\Federation\EntityStatement[] $entities
     * @return array<mixed>
     * @throws \RuntimeException If no statement in the chain carries the issuer's keys.
     */
    private function entityKeys(array $entities, int $afterIndex, string $entityId): array
    {
        for ($i = $afterIndex + 1; $i < count($entities); $i++) {
            if ($entities[$i]->getSubject() === $entityId) {
                return $entities[$i]->getJwks()->getValue();
            }
        }
        throw new \RuntimeException("Trust chain carries no keys for issuer '$entityId'");
    }

    protected function federation(): Federation
    {
        if ($this->federation === null) {
            /** @var ?Client $client */
            $client = $this->options['httpClient'] ?? null;
            $this->federation = new Federation(
                supportedAlgorithms: new SupportedAlgorithms(
                    new SignatureAlgorithmBag(...self::SUPPORTED_SIGNING_ALGORITHMS),
                ),
                cache: $this->cacheEnabled ? $this->cache() : null,
                client: $client,
            );
        }
        return $this->federation;
    }

    /**
     * Shares the FilesystemAdapter namespace with EntityStatementBuilder: both cache
     * federation artifacts for this module and neither key collides with the other.
     */
    protected function cache(): Psr16Cache
    {
        $cacheDir = $this->cacheDir
            ?? \SimpleSAML\Configuration::getInstance()->getString('cachedir') . '/authoauth2-federation';
        return new Psr16Cache(new FilesystemAdapter('authoauth2-federation', 0, $cacheDir));
    }
}
