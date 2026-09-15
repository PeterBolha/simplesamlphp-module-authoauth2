<?php

declare(strict_types=1);

namespace SimpleSAML\Module\authoauth2\Federation;

use DateInterval;
use SimpleSAML\Configuration;
use SimpleSAML\Error\ConfigurationError;
use SimpleSAML\Logger;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmBag;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmEnum;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Codebooks\EntityTypesEnum;
use SimpleSAML\OpenID\Federation;
use SimpleSAML\OpenID\Federation\EntityStatement;
use SimpleSAML\OpenID\SupportedAlgorithms;
use SimpleSAML\OpenID\ValueAbstracts\Factories\SignatureKeyPairBagFactory;
use SimpleSAML\OpenID\ValueAbstracts\KeyPairFilenameConfig;
use SimpleSAML\OpenID\ValueAbstracts\SignatureKeyPairBag;
use SimpleSAML\OpenID\ValueAbstracts\SignatureKeyPairConfig;
use SimpleSAML\OpenID\ValueAbstracts\SignatureKeyPairConfigBag;
use Symfony\Component\Cache\Adapter\FilesystemAdapter;
use Symfony\Component\Cache\Psr16Cache;

/**
 * Builds and signs this module's self-signed entity configuration statement
 * (OpenID Federation 1.0 §5.2), served at /.well-known/openid-federation.
 *
 * Config schema (module config file authoauth2.php, key 'federation'):
 *   entityId                string, required. Must be the public HTTPS URL of this
 *                           module instance; the statement is published under it.
 *   federationKeys          list, required. Each entry: privateKey (PEM path),
 *                           publicKey (PEM path), algorithm (default RS256),
 *                           keyId (default: JWK thumbprint), password (optional).
 *                           The first entry signs the statement; all public keys
 *                           are published in the jwks claim (key rollover). The
 *                           same public keys are published in the RP metadata
 *                           jwks: they double as the OIDC client keys the OP
 *                           uses to verify our request objects and client
 *                           assertions (automatic registration, §12.1).
 *   trustAnchors            list of trust anchor entity IDs
 *   authorityHints          list, defaults to trustAnchors
 *   lifetime                statement validity, ISO 8601 duration (default P1D)
 *   redirectUris            list, defaults to the module's linkback URL
 *   scopes                  list (default ['openid', 'profile'])
 *   tokenEndpointAuthMethod default 'private_key_jwt' (how this module's
 *                           federation provider authenticates to the token
 *                           endpoint; the federation key signs the assertion)
 *   idTokenSigningAlgs      list (default ['RS256'])
 *   trustMarks              static trust marks, passthrough list of
 *                           {trust_mark_type, trust_mark}
 *   additionalRpMetadata    raw openid_relying_party claims (snake_case), merged
 *                           over the generated ones; may include jwks or jwks_uri
 *                           for the OIDC client key
 *   additionalClaims        raw top-level payload claims, merged first (overridden
 *                           by the generated iss/sub/iat/exp/jti/jwks)
 *   cache                   bool, default true. Cache the signed statement until
 *                           near its exp, in a FilesystemAdapter under SSP's
 *                           cachedir (same pattern as the OIDC discovery cache).
 */
class EntityStatementBuilder
{
    /** Rebuild this many seconds before actual expiry so a cached token is never served stale. */
    private const EXPIRY_SAFETY_MARGIN_SECONDS = 60;

    private readonly string $entityId;

    /** @var list<array<string, mixed>> */
    private readonly array $keyConfigs;

    /** @var list<string> */
    private readonly array $authorityHints;

    private readonly DateInterval $lifetime;

    /** @var list<string> */
    private readonly array $redirectUris;

    /** @var list<string> */
    private readonly array $scopes;

    private readonly string $tokenEndpointAuthMethod;

    /** @var list<string> */
    private readonly array $idTokenSigningAlgs;

    /** @var list<array<string, mixed>> */
    private readonly array $trustMarks;

    /** @var array<string, mixed> */
    private readonly array $additionalRpMetadata;

    /** @var array<string, mixed> */
    private readonly array $additionalClaims;

    private readonly bool $cacheEnabled;

    private readonly string $cacheDir;

    private ?Federation $federation = null;

    private ?SignatureKeyPairBag $signatureKeyPairs = null;

    /**
     * @param array<string, mixed> $config the 'federation' config array
     * @param string|null $defaultRedirectUri linkback URL, used when redirectUris is not configured
     * @param string|null $cacheDir defaults to SSP cachedir + '/authoauth2-federation'
     */
    public function __construct(array $config, ?string $defaultRedirectUri = null, ?string $cacheDir = null)
    {
        if (!isset($config['entityId']) || !is_string($config['entityId']) || $config['entityId'] === '') {
            throw new ConfigurationError(
                'federation.entityId is required to publish an entity configuration statement',
            );
        }
        $this->entityId = $config['entityId'];

        if (
            !isset($config['federationKeys'])
            || !is_array($config['federationKeys'])
            || $config['federationKeys'] === []
        ) {
            throw new ConfigurationError(
                'federation.federationKeys must list at least one federation signing key pair',
            );
        }
        $this->keyConfigs = self::toAssocList($config['federationKeys']);
        if ($this->keyConfigs === []) {
            throw new ConfigurationError('federation.federationKeys contains no valid key entries');
        }
        foreach ($this->keyConfigs as $keyConfig) {
            $this->algorithmFor($keyConfig);
        }

        $trustAnchors = self::toStringList($config['trustAnchors'] ?? []);
        $hints = self::toStringList($config['authorityHints'] ?? []);
        $this->authorityHints = $hints !== [] ? $hints : $trustAnchors;

        $lifetime = (string)($config['lifetime'] ?? 'P1D');
        try {
            $this->lifetime = new DateInterval($lifetime);
        } catch (\Exception) {
            throw new ConfigurationError("federation.lifetime is not a valid ISO 8601 duration: $lifetime");
        }

        $redirectUris = self::toStringList($config['redirectUris'] ?? []);
        if ($redirectUris === [] && $defaultRedirectUri !== null && $defaultRedirectUri !== '') {
            $redirectUris = [$defaultRedirectUri];
        }
        $this->redirectUris = $redirectUris;
        if ($this->redirectUris === []) {
            throw new ConfigurationError(
                'federation.redirectUris is required when no default redirect URI is available',
            );
        }

        $scopes = self::toStringList($config['scopes'] ?? []);
        $this->scopes = $scopes !== [] ? $scopes : ['openid', 'profile'];
        $this->tokenEndpointAuthMethod = (string)($config['tokenEndpointAuthMethod'] ?? 'private_key_jwt');
        $idTokenAlgs = self::toStringList($config['idTokenSigningAlgs'] ?? []);
        $this->idTokenSigningAlgs = $idTokenAlgs !== [] ? $idTokenAlgs : ['RS256'];
        $this->trustMarks = array_values(array_filter(
            self::toAssocList($config['trustMarks'] ?? []),
            static fn(array $mark): bool => isset($mark['trust_mark_type'], $mark['trust_mark'])
                && is_string($mark['trust_mark_type'])
                && is_string($mark['trust_mark']),
        ));
        $this->additionalRpMetadata = self::toAssocArray($config['additionalRpMetadata'] ?? []);
        $this->additionalClaims = self::toAssocArray($config['additionalClaims'] ?? []);
        $this->cacheEnabled = (bool)($config['cache'] ?? true);
        $this->cacheDir = $cacheDir
            ?? Configuration::getInstance()->getString('cachedir') . '/authoauth2-federation';
    }

    public function getEntityId(): string
    {
        return $this->entityId;
    }

    /**
     * Build a fresh self-signed entity configuration statement.
     */
    public function build(): EntityStatement
    {
        $keyPair = $this->signatureKeyPairBag()->getFirstOrFail();
        $issuedAt = time();

        $payload = $this->additionalClaims;
        $payload[ClaimsEnum::Iss->value] = $this->entityId;
        $payload[ClaimsEnum::Sub->value] = $this->entityId;
        $payload[ClaimsEnum::Iat->value] = $issuedAt;
        $payload[ClaimsEnum::Exp->value] = $issuedAt + $this->lifetimeTotalSeconds();
        $payload[ClaimsEnum::Jti->value] = bin2hex(random_bytes(16));
        $payload[ClaimsEnum::Jwks->value] = $this->publicJwks();
        if ($this->authorityHints !== []) {
            $payload[ClaimsEnum::AuthorityHints->value] = $this->authorityHints;
        }
        if ($this->trustMarks !== []) {
            $payload[ClaimsEnum::TrustMarks->value] = $this->trustMarks;
        }
        $payload[ClaimsEnum::Metadata->value] = [
            EntityTypesEnum::OpenIdRelyingParty->value => $this->buildRpMetadata(),
        ];

        /** @var array<non-empty-string,mixed> $payload */
        $statement = $this->federation()->entityStatementFactory()->fromData(
            $keyPair->getKeyPair()->getPrivateKey(),
            $keyPair->getSignatureAlgorithm(),
            $payload,
            [ClaimsEnum::Kid->value => $keyPair->getKeyPair()->getKeyId()],
        );

        Logger::debug('authoauth2: built entity configuration statement for ' . $this->entityId);
        return $statement;
    }

    /**
     * Signed statement as a compact JWS, served from cache while comfortably valid.
     *
     * @return array{token: string, expiresIn: int}
     */
    public function getSerializedStatement(): array
    {
        $cacheKey = 'entity-config-' . sha1($this->entityId);
        if ($this->cacheEnabled) {
            $cached = $this->cache()->get($cacheKey);
            $expiresAt = is_array($cached) ? ($cached['expiresAt'] ?? 0) : 0;
            if (is_array($cached) && is_string($cached['token'] ?? null) && is_int($expiresAt)) {
                $expiresIn = $expiresAt - time();
                if ($expiresIn > 0) {
                    Logger::debug(
                        'authoauth2: serving cached entity configuration statement for ' . $this->entityId,
                    );
                    return ['token' => $cached['token'], 'expiresIn' => $expiresIn];
                }
            }
        }

        $statement = $this->build();
        $token = $statement->getToken();
        $expiresIn = $this->lifetimeTotalSeconds() - self::EXPIRY_SAFETY_MARGIN_SECONDS;

        if ($this->cacheEnabled && $expiresIn > 0) {
            // Absolute expiry, so a cache hit late in the lifetime reports the remaining time, not the original.
            $this->cache()->set($cacheKey, ['token' => $token, 'expiresAt' => time() + $expiresIn], $expiresIn);
        }

        return ['token' => $token, 'expiresIn' => $expiresIn];
    }

    /**
     * @return array<string, mixed>
     */
    protected function buildRpMetadata(): array
    {
        $metadata = [
            'application_type' => 'web',
            'grant_types' => ['authorization_code'],
            'response_types' => ['code'],
            'redirect_uris' => $this->redirectUris,
            'response_modes_supported' => ['query', 'form_post'],
            'scope' => implode(' ', $this->scopes),
            'token_endpoint_auth_method' => $this->tokenEndpointAuthMethod,
            'id_token_signing_alg_values_supported' => $this->idTokenSigningAlgs,
            // The federation keys double as OIDC client keys (§12.1); a
            // separately configured client key arrives via additionalRpMetadata.
            'jwks' => $this->publicJwks(),
        ];
        return array_merge($metadata, $this->additionalRpMetadata);
    }

    /**
     * @return array<string, mixed>
     */
    private function publicJwks(): array
    {
        return $this->federation()->jwksDecoratorFactory()->fromJwkDecorators(
            ...$this->signatureKeyPairBag()->getAllPublicKeys(),
        )->jsonSerialize();
    }

    protected function federation(): Federation
    {
        if ($this->federation === null) {
            $algorithms = [];
            foreach ($this->keyConfigs as $keyConfig) {
                $algorithms[] = $this->algorithmFor($keyConfig);
            }
            /** @var non-empty-list<SignatureAlgorithmEnum> $algorithms */
            $this->federation = new Federation(
                supportedAlgorithms: new SupportedAlgorithms(new SignatureAlgorithmBag(...$algorithms)),
                cache: $this->cacheEnabled ? $this->cache() : null,
            );
        }
        return $this->federation;
    }

    protected function signatureKeyPairBag(): SignatureKeyPairBag
    {
        if ($this->signatureKeyPairs === null) {
            $configs = [];
            foreach ($this->keyConfigs as $keyConfig) {
                $privateKey = $keyConfig['privateKey'] ?? null;
                $publicKey = $keyConfig['publicKey'] ?? null;
                if (!is_string($privateKey) || $privateKey === '' || !is_string($publicKey) || $publicKey === '') {
                    throw new ConfigurationError('Each federation key entry requires privateKey and publicKey paths');
                }
                $password = (isset($keyConfig['password']) && is_string($keyConfig['password'])
                    && $keyConfig['password'] !== '')
                    ? $keyConfig['password']
                    : null;
                $keyId = (isset($keyConfig['keyId']) && is_string($keyConfig['keyId']) && $keyConfig['keyId'] !== '')
                    ? $keyConfig['keyId']
                    : null;
                $configs[] = new SignatureKeyPairConfig(
                    $this->algorithmFor($keyConfig),
                    new KeyPairFilenameConfig($privateKey, $publicKey, $password, $keyId),
                );
            }
            $this->signatureKeyPairs = (new SignatureKeyPairBagFactory())->fromConfig(
                new SignatureKeyPairConfigBag(...$configs),
            );
        }
        return $this->signatureKeyPairs;
    }

    /**
     * @param array<string, mixed> $keyConfig
     */
    protected function algorithmFor(array $keyConfig): SignatureAlgorithmEnum
    {
        $configured = (string)($keyConfig['algorithm'] ?? 'RS256');
        $algorithm = SignatureAlgorithmEnum::tryFrom($configured);
        if ($algorithm === null || $algorithm->isNone()) {
            throw new ConfigurationError('Unsupported federation key algorithm: ' . $configured);
        }
        return $algorithm;
    }

    /**
     * @param mixed $value
     * @return list<string>
     */
    private static function toStringList(mixed $value): array
    {
        $strings = [];
        foreach (is_array($value) ? $value : [] as $item) {
            if (is_string($item)) {
                $strings[] = $item;
            }
        }
        return $strings;
    }

    /**
     * @param mixed $value
     * @return list<array<string, mixed>>
     */
    private static function toAssocList(mixed $value): array
    {
        $result = [];
        foreach (is_array($value) ? $value : [] as $item) {
            if (is_array($item)) {
                /** @var array<string, mixed> $item */
                $result[] = $item;
            }
        }
        return $result;
    }

    /**
     * @param mixed $value
     * @return array<string, mixed>
     */
    private static function toAssocArray(mixed $value): array
    {
        $result = [];
        foreach (is_array($value) ? $value : [] as $key => $item) {
            if (is_string($key)) {
                $result[$key] = $item;
            }
        }
        return $result;
    }

    protected function cache(): Psr16Cache
    {
        return new Psr16Cache(new FilesystemAdapter('authoauth2-federation', 0, $this->cacheDir));
    }

    private function lifetimeTotalSeconds(): int
    {
        $reference = time();
        return (new \DateTimeImmutable('@' . $reference))->add($this->lifetime)->getTimestamp() - $reference;
    }
}
