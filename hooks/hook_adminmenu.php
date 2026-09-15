<?php

declare(strict_types=1);

use SimpleSAML\Locale\Translate;
use SimpleSAML\Module;
use SimpleSAML\Module\authoauth2\Codebooks\RoutesEnum;
use SimpleSAML\XHTML\Template;

/** @noinspection PhpParameterByRefIsNotUsedAsReferenceInspection Reference is actually used by SimpleSAMLphp */
function authoauth2_hook_adminmenu(Template &$template): void
{
    $menuKey = 'menu';

    if (!isset($template->data[$menuKey]) || !is_array($template->data[$menuKey])) {
        return;
    }

    $federationMenuEntry = [
        'authoauth2' => [
            'url' => Module::getModuleURL('authoauth2/' . RoutesEnum::AdminStatus->value),
            'name' => Translate::noop('OpenID Connect Federation'),
        ],
    ];

    // Put our entry before the 'Log out' entry, if it exists.
    $logoutEntryKey = 'logout';
    $logoutEntryValue = null;
    if (
        array_key_exists($logoutEntryKey, $template->data[$menuKey]) &&
        is_array($template->data[$menuKey][$logoutEntryKey])
    ) {
        $logoutEntryValue = $template->data[$menuKey][$logoutEntryKey];
        unset($template->data[$menuKey][$logoutEntryKey]);
    }

    $template->data[$menuKey] += $federationMenuEntry;

    if ($logoutEntryValue !== null) {
        $template->data[$menuKey][$logoutEntryKey] = $logoutEntryValue;
    }

    $template->getLocalization()->addModuleDomain('authoauth2');
}
