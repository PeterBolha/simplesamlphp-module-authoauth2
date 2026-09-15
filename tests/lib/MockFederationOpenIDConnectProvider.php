<?php

declare(strict_types=1);

namespace Test\SimpleSAML;

use SimpleSAML\Module\authoauth2\Providers\FederationOpenIDConnectProvider;

/**
 * Federation provider double for auth-source tests: forces the POST front
 * channel on and hands back canned form data so the dispatch can be asserted.
 */
class MockFederationOpenIDConnectProvider extends FederationOpenIDConnectProvider
{
    public function requiresPostAuthorizationRequest(): bool
    {
        return true;
    }

    public function getAuthorizationFormData(array $options = []): array
    {
        return [
            'url' => 'https://op.example.org/authorize',
            'fields' => [
                'client_id' => 'https://rp.example.org/module.php/authoauth2',
                'response_type' => 'code',
                'request' => 'signed.request.object.jwt',
            ],
        ];
    }
}
