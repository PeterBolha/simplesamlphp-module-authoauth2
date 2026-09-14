<?php

declare(strict_types=1);

namespace SimpleSAML\Module\authoauth2\Providers;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use SimpleSAML\Configuration;
use SimpleSAML\Error\ConfigurationError;
use SimpleSAML\Logger;
use SimpleSAML\Module\authoauth2\Federation\OPMetadataResolver;

/**
 * OpenID Connect provider whose endpoints and signing keys come from OpenID
 * Federation instead of the OP's .well-known/openid-configuration document.
 *
 * The OP is identified by its federation Entity ID; all provider metadata is
 * the policy-resolved openid_provider metadata of a verified trust chain to a
 * configured Trust Anchor (OpenID Federation 1.0 §11.2). The classic
 * discovery-based path in OpenIDConnectProvider is untouched for
 * non-federation sources.
 *
 * Additional constructor options:
 *   opEntityId     string, optional. Federation Entity ID of the OP; defaults
 *                  to 'issuer'. Resolved metadata issuer MUST equal it (the
 *                  OP is its own subject; id_token iss is checked against it).
 *   federation     array, required. trustAnchors (list, required) plus
 *                  cache/cacheDir passthrough — see OPMetadataResolver.
 */
class FederationOpenIDConnectProvider extends OpenIDConnectProvider
{
    /**
     * kty/crv -> default signature algorithm, for JWKS entries without an
     * explicit "alg" (optional per RFC 7517 §4.4, but firebase/php-jwt needs
     * one to build a Key).
     */
    private const DEFAULT_ALGORITHMS = [
        'RSA' => 'RS256',
        'EC|P-256' => 'ES256',
        'EC|P-384' => 'ES384',
        'EC|P-521' => 'ES512',
    ];

    /**
     * Protected, not private: league's AbstractProvider writes recognized option
     * keys ('opEntityId') through the GuardedPropertyTrait magic setter, which
     * runs in the parent class context and fails on private properties.
     */
    protected string $opEntityId;

    /** Overridable seam for tests; production always uses the trust chain resolver. */
    protected OPMetadataResolver $metadataResolver;

    public function __construct(array $options = [], array $collaborators = [])
    {
        $config = Configuration::loadFromArray($options);

        $federationConfig = $config->getOptionalArray('federation', null);
        if ($federationConfig === null) {
            throw new ConfigurationError(
                'The federation option (with trustAnchors) is required by FederationOpenIDConnectProvider',
            );
        }
        // Either opEntityId or issuer names the OP; issuer stays required for the
        // base class, which uses it as the id_token iss value.
        $opEntityId = $config->getOptionalString('opEntityId', $config->getOptionalString('issuer', ''));
        if ($opEntityId === '') {
            throw new ConfigurationError(
                'FederationOpenIDConnectProvider requires opEntityId (or issuer) to identify the OP',
            );
        }
        $this->opEntityId = $opEntityId;
        /** @var array<string, mixed> $federationConfig Config arrays from PHP files are string-keyed. */
        $this->metadataResolver = new OPMetadataResolver($federationConfig, [
            'httpClient' => $collaborators['httpClient'] ?? null,
        ]);

        // In federation mode the issuer is the OP entity ID; drop any discovery
        // URL the classic path would otherwise build from it.
        $options['issuer'] = $opEntityId;
        unset($options['discoveryUrl']);

        parent::__construct($options, $collaborators);
    }

    public function getOPEntityId(): string
    {
        return $this->opEntityId;
    }

    /**
     * Build the OpenID configuration from the resolved federation metadata
     * rather than fetching the OP's discovery document.
     *
     * @throws IdentityProviderException
     */
    protected function getOpenIDConfiguration(): Configuration
    {
        if (isset($this->openIdConfiguration)) {
            return $this->openIdConfiguration;
        }

        try {
            $metadata = $this->metadataResolver->resolveOPMetadata($this->opEntityId);
        } catch (\Exception $e) {
            throw new IdentityProviderException(
                'Unable to resolve OP metadata through the federation trust chain: ' . $e->getMessage(),
                0,
                $e->getMessage(),
            );
        }

        if (($metadata['issuer'] ?? null) !== $this->opEntityId) {
            throw new IdentityProviderException(
                'Resolved OP metadata issuer does not match the OP entity ID ' . $this->opEntityId,
                0,
                $metadata['issuer'] ?? null,
            );
        }

        $this->assertUsableEndpoints($metadata);

        $this->openIdConfiguration = Configuration::loadFromArray($metadata);
        return $this->openIdConfiguration;
    }

    /**
     * Signing keys from the federation-resolved JWKS when the metadata carries
     * one inline (no extra fetch), otherwise from the resolved jwks_uri — which
     * the existing HTTP cache middleware caches like any other OIDC fetch.
     *
     * @return array<string, Key> kid-indexed keys for firebase/php-jwt
     * @throws IdentityProviderException
     */
    protected function getSigningKeyObjects(): array
    {
        $config = $this->getOpenIDConfiguration();

        $jwks = $config->getOptionalArray('jwks', []);
        if ($jwks === []) {
            $jwksUri = $config->getString('jwks_uri');
            /** @var array<array-key, mixed> $fetched */
            $fetched = $this->getParsedResponse($this->getRequest('GET', $jwksUri));
            $jwks = $fetched;
        }

        try {
            return $this->parseJwks($jwks);
        } catch (\UnexpectedValueException | \DomainException $e) {
            throw new IdentityProviderException('Unable to parse OP signing keys: ' . $e->getMessage(), 0, $jwks);
        }
    }

    /**
     * id_token verification with federation keys: unlike the classic path this
     * accepts the signing algorithms the resolved metadata advertises (EC and
     * PS included, not just RS256) and uses the JWKS as published through the
     * trust chain.
     *
     * @throws IdentityProviderException
     */
    public function verifyIdToken(string $id_token): void
    {
        try {
            $keys = $this->getSigningKeyObjects();
            $claims = JWT::decode($id_token, $keys);
            $aud = is_array($claims->aud) ? $claims->aud : [$claims->aud];

            if (!in_array($this->clientId, $aud)) {
                throw new IdentityProviderException('ID token has incorrect audience', 0, $claims->aud);
            }
            if ($this->validateIssuer && $claims->iss !== $this->opEntityId) {
                throw new IdentityProviderException(
                    "ID token has incorrect issuer. Expected '{$this->opEntityId}' received '{$claims->iss}'",
                    0,
                    $claims->iss,
                );
            }
        } catch (\UnexpectedValueException $e) {
            throw new IdentityProviderException('ID token validation failed', 0, $e->getMessage());
        }
    }

    /**
     * The endpoints league/the flow actually call must be present and https,
     * mirroring the validation the classic discovery path applies.
     *
     * @param array<string, mixed> $metadata
     * @throws IdentityProviderException
     */
    private function assertUsableEndpoints(array $metadata): void
    {
        foreach (['authorization_endpoint', 'token_endpoint', 'userinfo_endpoint'] as $key) {
            $value = $metadata[$key] ?? null;
            if (!is_string($value) || !str_starts_with($value, 'https://')) {
                throw new IdentityProviderException(
                    "Resolved OP metadata is missing a usable https $key",
                    0,
                    $value,
                );
            }
        }
        $hasJwks = is_array($metadata['jwks'] ?? null) && ($metadata['jwks'] !== []);
        $jwksUri = $metadata['jwks_uri'] ?? null;
        if (!$hasJwks && (!is_string($jwksUri) || !str_starts_with($jwksUri, 'https://'))) {
            throw new IdentityProviderException(
                'Resolved OP metadata has neither inline jwks nor a usable https jwks_uri',
                0,
                $jwksUri,
            );
        }
    }

    /**
     * @param array<mixed> $jwks
     * @return array<string, Key>
     * @throws \UnexpectedValueException
     */
    private function parseJwks(array $jwks): array
    {
        $keys = [];
        foreach ($jwks['keys'] ?? [] as $jwk) {
            /** @var array<string, mixed> $jwk */
            if (($jwk['use'] ?? 'sig') !== 'sig' || ($jwk['kid'] ?? null) === null) {
                Logger::warning('authoauth2: skipping unusable OP JWK (no kid or not a signing key)');
                continue;
            }
            $hasAlg = isset($jwk['alg']) && is_string($jwk['alg']);
            if (!$hasAlg) {
                $default = $this->defaultAlgorithmFor((string)$jwk['kty'], (string)($jwk['crv'] ?? ''));
                if ($default === null) {
                    Logger::warning(
                        'authoauth2: skipping OP JWK without alg of unsupported type '
                        . (string)($jwk['kty'] ?? 'unknown'),
                    );
                    continue;
                }
                $jwk['alg'] = $default;
            }
            $key = JWK::parseKey($jwk);
            if ($key !== null) {
                $keys[(string)$jwk['kid']] = $key;
            }
        }
        if ($keys === []) {
            throw new \UnexpectedValueException('OP JWKS contained no usable signing keys');
        }
        return $keys;
    }

    private function defaultAlgorithmFor(string $kty, string $crv): ?string
    {
        return self::DEFAULT_ALGORITHMS["$kty|$crv"] ?? self::DEFAULT_ALGORITHMS[$kty] ?? null;
    }
}
