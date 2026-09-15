<?php

declare(strict_types=1);

namespace SimpleSAML\Module\authoauth2\Auth\Source;

use GuzzleHttp\HandlerStack;
use Kevinrob\GuzzleCache\CacheMiddleware;
use Kevinrob\GuzzleCache\Storage\Psr6CacheStorage;
use Kevinrob\GuzzleCache\Strategy\PrivateCacheStrategy;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Token\AccessToken;
use SimpleSAML\Auth\State;
use SimpleSAML\Configuration;
use SimpleSAML\Logger;
use SimpleSAML\Module;
use SimpleSAML\Module\authoauth2\Codebooks\LegacyRoutesEnum;
use SimpleSAML\Module\authoauth2\Codebooks\RoutesEnum;
use SimpleSAML\Module\authoauth2\Providers\FederationOpenIDConnectProvider;
use SimpleSAML\Module\authoauth2\Providers\OpenIDConnectProvider;
use SimpleSAML\Utils\HTTP;
use Symfony\Component\Cache\Adapter\FilesystemAdapter;

/**
 * Authentication source to authenticate with a generic OpenID Connect idp
 *
 * @package SimpleSAML\Module\authoauth2
 */
class OpenIDConnect extends OAuth2
{
    /** String used to identify our states. */
    public const STAGE_LOGOUT = 'authouath2:logout';
    protected static string $defaultProviderClass = OpenIDConnectProvider::class;

    /**
     * Get the provider to use to talk to the OAuth2 server.
     * Only visible for testing
     *
     * Since SSP may serialize Auth modules we don't assign the potentially unserializable provider to a field.
     *
     * @param   Configuration  $config
     *
     * @return AbstractProvider
     * @throws \Exception
     */
    public function getProvider(Configuration $config): AbstractProvider
    {
        $config = $this->applyFederationOptions($config);
        $provider = parent::getProvider($config);
        $httpClient = $provider->getHttpClient();
        /** @psalm-suppress DeprecatedMethod */
        $handler = $httpClient->getConfig('handler');
        if (!($handler instanceof HandlerStack)) {
            $newhandler = HandlerStack::create();
            /** @psalm-suppress MixedArgument */
            $newhandler->push($handler);
            /** @psalm-suppress DeprecatedMethod */
            $httpClient->getConfig()['handler'] = $newhandler;
            $handler = $newhandler;
        }
        $cacheDir = Configuration::getInstance()->getString('cachedir') . '/oidc-cache';
        $handler->push(
            new CacheMiddleware(
                new PrivateCacheStrategy(
                    new Psr6CacheStorage(
                        new FilesystemAdapter('', 0, $cacheDir)
                    )
                ),
            )
        );
        return $provider;
    }

    /**
     * Federation sources using automatic registration (§12.1) deliver the
     * authorization request as a POST form (the signed Request Object with its
     * trust chain does not fit a redirect URL); all other sources keep the
     * classic GET redirect.
     */
    public function authenticate(array &$state): void
    {
        $provider = $this->getProvider($this->config);
        if (
            !($provider instanceof FederationOpenIDConnectProvider)
            || !$provider->requiresPostAuthorizationRequest()
        ) {
            parent::authenticate($state);
            return;
        }

        $state[self::AUTHID] = $this->getAuthId();
        $stateID = State::saveState($state, self::STAGE_INIT);

        $options = $this->config->getOptionalArray('urlAuthorizeOptions', []);
        $options = array_merge($options, $this->getAuthorizeOptionsFromState($state));
        $options['state'] = self::STATE_PREFIX . '|' . $stateID;

        $data = $provider->getAuthorizationFormData($options);
        Logger::debug('authoauth2: ' . $this->getLabel() . ' posting authorization request to ' . $data['url']);

        // must run before submitPOSTData(), which renders a page and exits
        $this->saveCodeChallengeFromProvider($provider);

        $this->getHttp()->submitPOSTData($data['url'], $data['fields']);
    }

    /**
     * If the source config has a 'federation' option, route this source through
     * the federation-aware provider: OP metadata is resolved over a verified
     * trust chain instead of the .well-known discovery document.
     *
     * Source config shape:
     *   'federation' => [
     *       'trustAnchors' => ['https://ta.example.org'],  // required
     *       'cache' => true,                               // optional
     *       'cacheDir' => '/path',                         // optional
     *   ],
     *   'opEntityId' => 'https://op.example.org',          // optional; defaults to 'issuer'
     *
     * An explicit providerClass always wins (it may itself be the federation
     * provider or a further subclass of it).
     */
    private function applyFederationOptions(Configuration $config): Configuration
    {
        if ($config->getOptionalArray('federation', null) === null || $config->hasValue('providerClass')) {
            return $config;
        }
        $options = $config->toArray();
        $options['providerClass'] = FederationOpenIDConnectProvider::class;
        return Configuration::loadFromArray($options, 'authsources:openidconnect:federation');
    }

    /**
     * Convert values from the state parameter of the authenticated call into options to the authorization request.
     *
     * Any parameter prefixed with oidc: are added (without the prefix), in
     * addition, isPassive and ForceAuthn are converted into prompt=none and
     * prompt=login respectively
     *
     * @param array $state
     * @return array
     */
    protected function getAuthorizeOptionsFromState(array &$state): array
    {
        $result = [];

        /** @var array|string $value */
        foreach ($state as $key => $value) {
            if (
                \is_string($key)
                && strncmp($key, 'oidc:', 5) === 0
            ) {
                $result[substr($key, 5)] = $value;
            }
        }
        if (\array_key_exists('ForceAuthn', $state) && $state['ForceAuthn']) {
            $result['prompt'] = 'login';
        }
        if (\array_key_exists('isPassive', $state) && $state['isPassive']) {
            $result['prompt'] = 'none';
        }
        return $result;
    }


    /**
     * This method is overriding the default empty implementation to parse attributes received in the id_token, and
     * place them into the attributes array.
     *
     * @inheritdoc
     */
    protected function postFinalStep(AccessToken $accessToken, AbstractProvider $provider, array &$state): void
    {
        $prefix = $this->getAttributePrefix();
        $id_token = (string)$accessToken->getValues()['id_token'];
        $id_token_claims = $this->extraIdTokenAttributes($id_token);
        $state['Attributes'] = array_merge($this->convertResourceOwnerAttributes(
            $id_token_claims,
            $prefix . 'id_token' . '.'
        ), (array)$state['Attributes']);
        $state['id_token'] = $id_token;
        $state['PersistentAuthData'][] = 'id_token';
        $state['LogoutState'] = ['id_token' => $id_token];
    }

    /**
     * Log out from upstream idp if possible
     *
     * @param array &$state Information about the current logout operation.
     * @return void
     */
    public function logout(array &$state): void
    {
        $providerLabel = $this->getLabel();
        if (array_key_exists('oidc:localLogout', $state) && $state['oidc:localLogout'] === true) {
            Logger::debug("authoauth2: $providerLabel OP initiated logout");
            return;
        }
        $provider = $this->getProvider($this->config);
        if (!$provider instanceof OpenIDConnectProvider) {
            Logger::warning('OIDC provider is wrong class');
            return;
        }
        $endSessionEndpoint = $provider->getEndSessionEndpoint();
        if (!$endSessionEndpoint) {
            Logger::debug("authoauth2: $providerLabel OP does not provide an 'end_session_endpoint'," .
                          " not doing anything for logout");
            return;
        }

        if (!array_key_exists('id_token', $state)) {
            Logger::debug("authoauth2: $providerLabel No id_token in state, not doing anything for logout");
            return;
        }
        $id_token = (string)$state['id_token'];

        $postLogoutUrl = $this->config->getOptionalString('postLogoutRedirectUri', null);
        if (!$postLogoutUrl) {
            $logoutRoute = $this->config->getOptionalBoolean('useLegacyRoutes', false) ?
                LegacyRoutesEnum::LegacyLoggedOut->value : RoutesEnum::LoggedOut->value;
            $postLogoutUrl = Module::getModuleURL("authoauth2/$logoutRoute");
        }

        // We are going to need the authId in order to retrieve this authentication source later, in the callback
        $state[self::AUTHID] = $this->getAuthId();

        $stateID = State::saveState($state, self::STAGE_LOGOUT);
        // We use the real HTTP class rather than the injected one to avoid having to mock/stub
        // this method for tests
        $endSessionURL = (new HTTP())->addURLParameters($endSessionEndpoint, [
            'id_token_hint' => $id_token,
            'post_logout_redirect_uri' => $postLogoutUrl,
            'state' => self::STATE_PREFIX . '-' . $stateID,
        ]);
        $this->getHttp()->redirectTrustedURL($endSessionURL);
        // @codeCoverageIgnoreStart
    }
}
