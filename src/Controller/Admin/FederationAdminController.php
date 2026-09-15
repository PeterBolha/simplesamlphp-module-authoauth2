<?php

declare(strict_types=1);

namespace SimpleSAML\Module\authoauth2\Controller\Admin;

use SimpleSAML\Configuration;
use SimpleSAML\Error\NotFound;
use SimpleSAML\Module;
use SimpleSAML\Module\authoauth2\Codebooks\RoutesEnum;
use SimpleSAML\Module\authoauth2\Federation\FederationStatusService;
use SimpleSAML\XHTML\Template;
use Symfony\Component\HttpFoundation\Request;
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

        $tpl = new Template($this->config, 'authoauth2:admin/status.twig');
        $tpl->data['status'] = $status->getStatus();
        $tpl->data['statusUrl'] = $this->moduleUrl(RoutesEnum::AdminStatus);
        $tpl->data['trustChainTestUrl'] = $this->moduleUrl(RoutesEnum::AdminTestTrustChainResolution);
        return $tpl;
    }

    private function moduleUrl(RoutesEnum $route): string
    {
        return Module::getModuleURL('authoauth2/' . $route->value);
    }
}
