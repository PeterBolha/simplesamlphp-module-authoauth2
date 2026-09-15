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
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmBag;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmEnum;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Codebooks\ClientAssertionTypesEnum;
use SimpleSAML\OpenID\Codebooks\ParamsEnum;
use SimpleSAML\OpenID\Core;
use SimpleSAML\OpenID\Federation;
use SimpleSAML\OpenID\SupportedAlgorithms;
use SimpleSAML\OpenID\ValueAbstracts\Factories\SignatureKeyPairBagFactory;
use SimpleSAML\OpenID\ValueAbstracts\KeyPairFilenameConfig;
use SimpleSAML\OpenID\ValueAbstracts\SignatureKeyPairBag;
use SimpleSAML\OpenID\ValueAbstracts\SignatureKeyPairConfig;
use SimpleSAML\OpenID\ValueAbstracts\SignatureKeyPairConfigBag;

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
 * Against an OP advertising Automatic Registration (OpenID Federation 1.0
 * §12.1) this provider speaks the federation dialect of the OIDC flow:
 *   - client_id is this RP's own federation Entity ID (§12.1, §3.2); no
 *     client secret exists or is needed — credentials are the federation key;
 *   - the authorization request is a signed Request Object (RFC 9101) with
 *     aud=OP, iss=RP entity ID, no sub, jti/exp, and our trust chain in the
 *     trust_chain JWS header (§12.1.1.1);
 *   - the token request authenticates with a private_key_jwt client_assertion
 *     signed with the same federation key (§12.1, RFC 7591 §auth).
 * The RP's entityID, federation keys and trust anchors come from the module's
 * own 'federation' config (authoauth2.php) — the same block that drives the
 * .well-known/openid-federation endpoint — so keys never live in authsources.
 *
 * Additional constructor options:
 *   opEntityId     string, optional. Federation Entity ID of the OP; defaults
 *                  to 'issuer'. Resolved metadata issuer MUST equal it (the
 *                  OP is its own subject; id_token iss is checked against it).
 *   federation     array, required. trustAnchors (list, required) plus
 *                  cache/cacheDir passthrough — see OPMetadataResolver.
 *                  entityId and federationKeys in this array override the
 *                  module-level values (tests); normally left out.
 */
class FederationOpenIDConnectProvider extends OpenIDConnectProvider
{
    /**
     * Validity of our signed request objects and client assertions. The spec
     * only requires exp to be present; short-lived limits replay windows.
     */
    private const JWT_LIFETIME_SECONDS = 300;

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

    /**
     * league mass-assigns every option onto an existing property; the
     * 'federation' OPTION must not overwrite our Federation object property.
     * (opEntityId stays unguarded on purpose — see its docblock.)
     */
    protected $guarded = ['federation'];

    /** Overridable seam for tests; production always uses the trust chain resolver. */
    protected OPMetadataResolver $metadataResolver;

    /** This RP's federation Entity ID — the client_id (§12.1). */
    protected string $rpEntityId = '';

    /** @var list<array<array-key, mixed>> federation key config entries (privateKey/publicKey/algorithm/keyId/password). */
    protected array $rpKeyConfigs = [];

    protected ?SignatureKeyPairBag $rpSignatureKeyPairs = null;

    protected ?Federation $federation = null;

    protected ?Core $signingToolkit = null;

    public function __construct(array $options = [], array $collaborators = [])
    {
        $config = Configuration::loadFromArray($options);

        /** @var array<string, mixed>|null $federationConfig Config arrays from PHP files are string-keyed. */
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
        $federationConfig = $this->mergeModuleFederationConfig($federationConfig);
        $this->metadataResolver = new OPMetadataResolver($federationConfig, [
            'httpClient' => $collaborators['httpClient'] ?? null,
        ]);

        $this->configureRpIdentity($federationConfig);
        // Automatic registration (§12.1): our entity ID is the client_id and no
        // secret exists. An explicit clientId is accepted for exotic setups only.
        if ($this->rpEntityId !== '' && !isset($options['clientId'])) {
            $options['clientId'] = $this->rpEntityId;
        }
        unset($options['clientSecret']);

        // In federation mode the issuer is the OP entity ID; drop any discovery
        // URL the classic path would otherwise build from it.
        $options['issuer'] = $opEntityId;
        unset($options['discoveryUrl']);

        parent::__construct($options, $collaborators);
    }

    /**
     * The module-level 'federation' block of authoauth2.php is the source of
     * truth — the same keys, entityId and trust anchors published at
     * .well-known/openid-federation; the source's own federation array may
     * override any of it (tests, multi-identity setups).
     *
     * @param array<string, mixed> $sourceFederation
     * @return array<string, mixed>
     */
    private function mergeModuleFederationConfig(array $sourceFederation): array
    {
        $moduleFederation = Configuration::getOptionalConfig('authoauth2.php')
            ->getOptionalArray('federation', null);
        if (!is_array($moduleFederation)) {
            return $sourceFederation;
        }
        /** @var array<string, mixed> $moduleFederation */
        return array_merge($moduleFederation, $sourceFederation);
    }

    /**
     * Load our federation identity (entityID + signing keys) from the merged
     * federation config; missing pieces only disable automatic registration.
     *
     * @param array<string, mixed> $federationConfig
     */
    private function configureRpIdentity(array $federationConfig): void
    {
        $entityId = $federationConfig['entityId'] ?? null;
        $keys = $federationConfig['federationKeys'] ?? null;
        if (!is_string($entityId) || $entityId === '' || !is_array($keys) || $keys === []) {
            // No identity we can sign with: automatic registration is off and
            // this source behaves like the pre-automatic federation provider
            // (metadata resolution only). A real federated OP rejects it.
            Logger::warning(
                'authoauth2: federation config lacks entityId/federationKeys;'
                . ' automatic registration (signed request objects, private_key_jwt) is disabled',
            );
            return;
        }
        $this->rpEntityId = $entityId;
        // Hand-written config: keep the array entries, drop junk.
        $this->rpKeyConfigs = array_values(array_filter($keys, 'is_array'));
        if ($this->rpKeyConfigs === []) {
            throw new ConfigurationError('federation.federationKeys contains no valid key entries');
        }
    }

    public function getOPEntityId(): string
    {
        return $this->opEntityId;
    }

    /** True when this provider has an RP identity and can sign federation requests. */
    public function isAutomaticRegistrationEnabled(): bool
    {
        return $this->rpEntityId !== '' && $this->rpKeyConfigs !== [];
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
     * Automatic registration (§12.1.1.1): the authorization request is a
     * signed Request Object whose trust_chain JWS header carries our verified
     * chain to the shared Trust Anchor; the OP establishes trust from the
     * request itself. A full chain in the request parameter overflows
     * practical URL length limits, so the front channel is delivered by POST
     * form (§12.1.1.2) — the auth source must send these fields to the URL
     * instead of redirecting to a GET authorization URL.
     *
     * @return array{url: string, fields: array<string, string>}
     * @throws IdentityProviderException
     */
    public function getAuthorizationFormData(array $options = []): array
    {
        $params = parent::getAuthorizationParameters($options);
        $requestObject = $this->buildRequestObject($params);

        $fields = [
            'client_id' => $this->rpEntityId,
            'scope' => (string)$params['scope'],
            'response_type' => (string)$params['response_type'],
            'redirect_uri' => (string)$params['redirect_uri'],
            'request' => $requestObject,
        ];
        if (isset($params['response_mode']) && $params['response_mode'] !== '') {
            $fields['response_mode'] = (string)$params['response_mode'];
        }

        return ['url' => $this->getBaseAuthorizationUrl(), 'fields' => $fields];
    }

    /**
     * Authorization requests must be POSTed (automatic registration is on);
     * otherwise the classic GET redirect applies.
     */
    public function requiresPostAuthorizationRequest(): bool
    {
        return $this->isAutomaticRegistrationEnabled();
    }

    /**
     * Sign the authorization parameters into a Request Object (§12.1.1.1):
     * aud=OP entity ID, iss=our entity ID, no sub, jti+exp; our trust chain in
     * the trust_chain JWS header. Algorithm: our first federation key (the
     * federation metadata advertises it; the demo OP accepts RS256). No `typ`
     * header: the library has no REQ+jwt type and the reference client omits
     * it; the OP must not require it.
     *
     * @param array<array-key, mixed> $params league authorization parameters
     * @throws IdentityProviderException
     */
    protected function buildRequestObject(array $params): string
    {
        $keyPair = $this->signatureKeyPairBag()->getFirstOrFail();
        $issuedAt = time();

        $payload = [];
        foreach (
            [
                ParamsEnum::ResponseType->value, ParamsEnum::ClientId->value,
                ParamsEnum::RedirectUri->value, ParamsEnum::Scope->value,
                ParamsEnum::State->value, ParamsEnum::Nonce->value,
                ParamsEnum::CodeChallenge->value, ParamsEnum::CodeChallengeMethod->value,
                'prompt', 'login_hint', ParamsEnum::ResponseMode->value,
                'claims', 'acr_values', 'resource',
            ] as $key
        ) {
            if (isset($params[$key]) && $params[$key] !== '') {
                $payload[$key] = $params[$key];
            }
        }
        // §12.1.1.1: client_id/iss are OUR entity ID; league's clientId is only
        // correct when configured from the same federation identity.
        $payload[ClaimsEnum::ClientId->value] = $this->rpEntityId;
        $payload[ClaimsEnum::Iss->value] = $this->rpEntityId;
        $payload[ClaimsEnum::Aud->value] = $this->opEntityId;
        $payload[ClaimsEnum::Iat->value] = $issuedAt;
        $payload[ClaimsEnum::Exp->value] = $issuedAt + self::JWT_LIFETIME_SECONDS;
        $payload[ClaimsEnum::Jti->value] = bin2hex(random_bytes(16));

        $header = [
            ClaimsEnum::Kid->value => $keyPair->getKeyPair()->getKeyId(),
            ClaimsEnum::TrustChain->value => $this->ownTrustChain(),
        ];

        try {
            $requestObject = $this->federation()->requestObjectFactory()->fromData(
                $keyPair->getKeyPair()->getPrivateKey(),
                $keyPair->getSignatureAlgorithm(),
                /** @var array<non-empty-string,mixed> $payload */
                $payload,
                /** @var array<non-empty-string,mixed> $header */
                $header,
            );
        } catch (\Exception $e) {
            throw new IdentityProviderException(
                'Unable to build signed federation request object: ' . $e->getMessage(),
                0,
                $e->getMessage(),
            );
        }
        return $requestObject->getToken();
    }

    /**
     * Our own verified trust chain as compact JWS list (leaf first), for the
     * trust_chain header. We chain to the same anchors the OP chain was
     * resolved against — anchors shared with the OP per §12.1.1.1; if the OP's
     * own chain ends elsewhere, the OP rejects our trust_chain, which is the
     * correct outcome.
     *
     * @return list<string>
     * @throws IdentityProviderException
     */
    protected function ownTrustChain(): array
    {
        try {
            return array_values($this->metadataResolver
                ->resolveChain($this->rpEntityId)
                ->jsonSerialize());
        } catch (\Exception $e) {
            throw new IdentityProviderException(
                'Unable to resolve our own trust chain for the authorization request: ' . $e->getMessage(),
                0,
                $e->getMessage(),
            );
        }
    }

    /**
     * Token-endpoint client authentication per §12.1: private_key_jwt — a
     * client_assertion signed with our federation key; no client secret is
     * sent (the OP never issues one).
     *
     * @throws IdentityProviderException
     */
    public function getAccessToken($grant, array $options = [])
    {
        if (!$this->isAutomaticRegistrationEnabled()) {
            return parent::getAccessToken($grant, $options);
        }

        $options[ParamsEnum::ClientAssertionType->value] = ClientAssertionTypesEnum::JwtBaerer->value;
        $options[ParamsEnum::ClientAssertion->value] = $this->buildClientAssertion();
        // Our entity ID as client_id; with the secret unset, league's null
        // client_secret drops out of the form-encoded body entirely.
        $options[ParamsEnum::ClientId->value] = $this->rpEntityId;

        return parent::getAccessToken($grant, $options);
    }

    /**
     * @throws IdentityProviderException
     */
    protected function buildClientAssertion(): string
    {
        $keyPair = $this->signatureKeyPairBag()->getFirstOrFail();
        $issuedAt = time();

        try {
            $assertion = $this->signingToolkit()->clientAssertionFactory()->fromData(
                $keyPair->getKeyPair()->getPrivateKey(),
                $keyPair->getSignatureAlgorithm(),
                [
                    ClaimsEnum::Iss->value => $this->rpEntityId,
                    ClaimsEnum::Sub->value => $this->rpEntityId,
                    ClaimsEnum::Aud->value => $this->opEntityId,
                    ClaimsEnum::Jti->value => bin2hex(random_bytes(16)),
                    ClaimsEnum::Iat->value => $issuedAt,
                    ClaimsEnum::Exp->value => $issuedAt + self::JWT_LIFETIME_SECONDS,
                ],
                [ClaimsEnum::Kid->value => $keyPair->getKeyPair()->getKeyId()],
            );
        } catch (\Exception $e) {
            throw new IdentityProviderException(
                'Unable to build federation client assertion: ' . $e->getMessage(),
                0,
                $e->getMessage(),
            );
        }
        return $assertion->getToken();
    }

    protected function federation(): Federation
    {
        if ($this->federation === null) {
            /** @var non-empty-list<SignatureAlgorithmEnum> $algorithms */
            $algorithms = [];
            foreach ($this->rpKeyConfigs as $keyConfig) {
                $algorithms[] = $this->algorithmFor($keyConfig);
            }
            $this->federation = new Federation(
                supportedAlgorithms: new SupportedAlgorithms(new SignatureAlgorithmBag(...$algorithms)),
            );
        }
        return $this->federation;
    }

    /**
     * Factories for building and signing OUR OWN JWTs (client assertions,
     * request objects) over our federation keys. That is the library's Core
     * entry point; Federation (above) covers trust-material *parsing* instead.
     */
    protected function signingToolkit(): Core
    {
        if ($this->signingToolkit === null) {
            $algorithms = [];
            foreach ($this->rpKeyConfigs as $keyConfig) {
                $algorithms[] = $this->algorithmFor($keyConfig);
            }
            /** @var non-empty-list<SignatureAlgorithmEnum> $algorithms */
            $this->signingToolkit = new Core(
                supportedAlgorithms: new SupportedAlgorithms(new SignatureAlgorithmBag(...$algorithms)),
            );
        }
        return $this->signingToolkit;
    }

    protected function signatureKeyPairBag(): SignatureKeyPairBag
    {
        if ($this->rpSignatureKeyPairs === null) {
            $configs = [];
            foreach ($this->rpKeyConfigs as $keyConfig) {
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
            $this->rpSignatureKeyPairs = (new SignatureKeyPairBagFactory())->fromConfig(
                new SignatureKeyPairConfigBag(...$configs),
            );
        }
        return $this->rpSignatureKeyPairs;
    }

    /**
     * @param array<array-key, mixed> $keyConfig
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
