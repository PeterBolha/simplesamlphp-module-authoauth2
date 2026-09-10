<?php

declare(strict_types=1);

namespace SimpleSAML\Module\authoauth2\Controller;

use SimpleSAML\Configuration;
use SimpleSAML\Error\NotFound;
use SimpleSAML\Logger;
use SimpleSAML\Module;
use SimpleSAML\Module\authoauth2\Federation\EntityStatementBuilder;
use Symfony\Component\HttpFoundation\Response;

/**
 * Serves this instance's self-signed entity configuration statement, making the
 * module discoverable as an OpenID Federation entity.
 */
class FederationController
{
    public function entityConfiguration(): Response
    {
        $moduleConfig = Configuration::getOptionalConfig('authoauth2.php');
        $federationConfig = $moduleConfig->getOptionalArray('federation', null);
        if ($federationConfig === null) {
            Logger::warning('authoauth2: federation endpoint requested but no federation config is present');
            throw new NotFound('Federation is not configured for this module.');
        }

        try {
            /** @psalm-suppress MixedArgumentTypeCoercion */
            $builder = new EntityStatementBuilder(
                $federationConfig,
                Module::getModuleURL('authoauth2/linkback'),
            );
            $statement = $builder->getSerializedStatement();
        } catch (\Exception $e) {
            Logger::error('authoauth2: failed to build entity configuration statement: ' . $e->getMessage());
            throw new NotFound('This entity does not publish an entity configuration statement.');
        }

        return new Response($statement['token'], 200, [
            'Content-Type' => 'application/entity-statement+jwt',
            'Cache-Control' => 'public, max-age=' . $statement['expiresIn'],
        ]);
    }
}
