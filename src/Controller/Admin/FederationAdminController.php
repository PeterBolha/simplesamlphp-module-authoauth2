<?php

declare(strict_types=1);

namespace SimpleSAML\Module\authoauth2\Controller\Admin;

use SimpleSAML\Configuration;
use SimpleSAML\Error\NotFound;
use SimpleSAML\Module\authoauth2\Codebooks\RoutesEnum;
use SimpleSAML\Module\authoauth2\Federation\FederationStatusService;
use Symfony\Component\HttpFoundation\Response;

/**
 * Read-only overview of this instance's OpenID Federation RP configuration.
 */
class FederationAdminController
{
    use AdminTrait;

    /** @var \SimpleSAML\Configuration */
    protected Configuration $config;

    public function __construct(?Configuration $config = null)
    {
        $this->config = $config ?? Configuration::getInstance();
        $this->requireAdmin();
    }

    public function status(): Response
    {
        $status = FederationStatusService::fromConfig();
        if ($status === null) {
            throw new NotFound('Federation is not configured for this module.');
        }

        return $this->renderAdminPage(
            $this->config,
            'authoauth2:admin/status.twig',
            [
                'status' => $status->getStatus(),
            ],
            RoutesEnum::AdminStatus,
        );
    }
}
