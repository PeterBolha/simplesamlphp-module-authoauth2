<?php

declare(strict_types=1);

use SimpleSAML\Configuration;
use SimpleSAML\Locale\Translate;
use SimpleSAML\Module;
use SimpleSAML\Module\authoauth2\Codebooks\RoutesEnum;
use SimpleSAML\XHTML\Template;

function authoauth2_hook_federationpage(Template $template): void
{
    // Without federation config our status page 404s; don't offer a dead tile.
    $federationConfig = Configuration::getOptionalConfig('authoauth2.php')
        ->getOptionalArray('federation', null);
    if ($federationConfig === null) {
        return;
    }

    if (!is_array($template->data['links'] ?? null)) {
        $template->data['links'] = [];
    }

    $template->data['links'][] = [
        'href' => Module::getModuleURL('authoauth2/' . RoutesEnum::AdminStatus->value),
        'text' => Translate::noop('OpenID Connect Federation RP'),
    ];
}
