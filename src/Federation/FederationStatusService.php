<?php

declare(strict_types=1);

namespace SimpleSAML\Module\authoauth2\Federation;

use SimpleSAML\Configuration;
use SimpleSAML\Logger;
use SimpleSAML\Module;

/**
 * Read-only overview of this instance's federation setup for the admin status
 * page: published entity, keys, trust anchors, statement lifetime and the
 * authsources that use federation. Never exposes private key material.
 */
class FederationStatusService
{
    /**
     * @param array<string, mixed> $federationConfig the module's 'federation' config array
     * @param array<string, mixed>|null $authSourcesConfig the full authsources.php array, injectable for tests
     */
    public function __construct(
        private readonly array $federationConfig,
        private readonly ?array $authSourcesConfig = null,
    ) {
    }

    public static function fromConfig(): ?self
    {
        $moduleConfig = Configuration::getOptionalConfig('authoauth2.php');
        /** @var array<string, mixed>|null $federationConfig Config arrays from PHP files are string-keyed. */
        $federationConfig = $moduleConfig->getOptionalArray('federation', null);
        if ($federationConfig === null) {
            return null;
        }

        try {
            $authSources = Configuration::getConfig('authsources.php')->toArray();
        } catch (\Exception $e) {
            Logger::warning('authoauth2: could not read authsources.php for the federation status page: '
                . $e->getMessage());
            $authSources = null;
        }

        /** @var array<string, mixed> $authSources */
        return new self($federationConfig, $authSources);
    }

    /**
     * @return array<string, mixed> everything the status template needs
     */
    public function getStatus(): array
    {
        $trustMarks = $this->federationConfig['trustMarks'] ?? [];
        return [
            'entityId' => (string)($this->federationConfig['entityId'] ?? ''),
            'keys' => $this->keySummary(),
            'trustAnchors' => $this->stringList('trustAnchors'),
            // Same default as EntityStatementBuilder: hints fall back to the anchors.
            'authorityHints' => $this->stringList('authorityHints') !== []
                ? $this->stringList('authorityHints')
                : $this->stringList('trustAnchors'),
            'lifetime' => (string)($this->federationConfig['lifetime'] ?? 'P1D'),
            'scopes' => $this->stringList('scopes'),
            'redirectUris' => $this->stringList('redirectUris'),
            'tokenEndpointAuthMethod' => (string)($this->federationConfig['tokenEndpointAuthMethod']
                ?? 'private_key_jwt'),
            'trustMarkCount' => is_array($trustMarks) ? count($trustMarks) : 0,
            'cacheEnabled' => (bool)($this->federationConfig['cache'] ?? true),
            'statement' => $this->statementSummary(),
            'authSources' => $this->federationAuthSources(),
        ];
    }

    /**
     * @return list<array{algorithm: string, keyId: string, publicKey: string, publicKeyExists: bool}>
     */
    private function keySummary(): array
    {
        $summary = [];
        foreach (
            is_array($this->federationConfig['federationKeys'] ?? null)
            ? $this->federationConfig['federationKeys'] : [] as $keyConfig
        ) {
            if (!is_array($keyConfig)) {
                continue;
            }
            $publicKey = isset($keyConfig['publicKey']) && is_string($keyConfig['publicKey'])
                ? $keyConfig['publicKey'] : '';
            $summary[] = [
                'algorithm' => (string)($keyConfig['algorithm'] ?? 'RS256'),
                // Empty when the key id is derived from the JWK thumbprint.
                'keyId' => isset($keyConfig['keyId']) && is_string($keyConfig['keyId'])
                    ? $keyConfig['keyId'] : '',
                'publicKey' => $publicKey,
                'publicKeyExists' => $publicKey !== '' && file_exists($publicKey),
            ];
        }
        return $summary;
    }

    /**
     * Decode the payload of the currently served statement for its validity
     * window. Never builds a statement that could not be built anyway.
     *
     * @return array{issuedAt: int|null, expiresAt: int|null, secondsRemaining: int|null, error: string|null}
     */
    private function statementSummary(): array
    {
        $empty = ['issuedAt' => null, 'expiresAt' => null, 'secondsRemaining' => null, 'error' => null];
        try {
            $builder = new EntityStatementBuilder(
                $this->federationConfig,
                Module::getModuleURL('authoauth2/linkback'),
            );
            $token = $builder->getSerializedStatement()['token'];
            $payloadPart = explode('.', $token)[1] ?? '';
            $payload = json_decode(base64_decode(strtr($payloadPart, '-_', '+/'), true) ?: '', true);
            if (!is_array($payload)) {
                return ['error' => 'statement payload could not be decoded'] + $empty;
            }
            $issuedAt = isset($payload['iat']) ? (int)$payload['iat'] : null;
            $expiresAt = isset($payload['exp']) ? (int)$payload['exp'] : null;
            return [
                'issuedAt' => $issuedAt,
                'expiresAt' => $expiresAt,
                'secondsRemaining' => $expiresAt !== null ? max(0, $expiresAt - time()) : null,
                'error' => null,
            ];
        } catch (\Exception $e) {
            return ['error' => $e->getMessage()] + $empty;
        }
    }

    /**
     * Authsources of this module that carry a federation option (i.e. talk to
     * an OP through trust chains rather than static client credentials only).
     *
     * @return list<array{name: string, issuer: string, hasOwnTrustAnchors: bool}>
     */
    private function federationAuthSources(): array
    {
        $found = [];
        foreach ($this->authSourcesConfig ?? [] as $name => $definition) {
            if (!is_array($definition) || !is_string($definition[0] ?? null)) {
                continue;
            }
            $type = (string)$definition[0];
            if (!str_starts_with(strtolower($type), 'authoauth2:')) {
                continue;
            }
            $federation = $definition['federation'] ?? null;
            if (!is_array($federation)) {
                continue;
            }
            $issuer = isset($definition['issuer']) && is_string($definition['issuer'])
                ? $definition['issuer'] : '';
            $found[] = [
                'name' => $name,
                'issuer' => $issuer,
                'hasOwnTrustAnchors' => isset($federation['trustAnchors'])
                    && is_array($federation['trustAnchors'])
                    && $federation['trustAnchors'] !== [],
            ];
        }
        return $found;
    }

    /**
     * @return list<string>
     */
    private function stringList(string $key): array
    {
        $value = $this->federationConfig[$key] ?? [];
        if (!is_array($value)) {
            return [];
        }
        return array_values(array_filter($value, 'is_string'));
    }
}
