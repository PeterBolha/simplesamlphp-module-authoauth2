<?php

declare(strict_types=1);

namespace SimpleSAML\Module\authoauth2\Controller\Admin;

use SimpleSAML\Configuration;
use SimpleSAML\Locale\Translate;
use SimpleSAML\Module;
use SimpleSAML\Module\admin\Controller\Menu as SspAdminMenu;
use SimpleSAML\Utils\Auth;
use SimpleSAML\XHTML\Template;

/**
 * Guards the admin federation pages with SSP's admin authentication and
 * renders them inside the admin theme (horizontal tab menu), mirroring how
 * the oidc module builds its admin pages.
 */
trait AdminTrait
{
    protected function requireAdmin(): void
    {
        (new Auth())->requireAdmin();
    }

    /**
     * @param array<string, mixed> $data
     */
    protected function renderAdminPage(
        Configuration $config,
        string $templateName,
        array $data,
    ): Template {
        $tpl = new Template($config, $templateName);

        if (Module::isModuleEnabled('admin')) {
            // Mirrors the oidc TemplateFactory: pull in the admin module's
            // templates (menu include) and rebuild the SSP admin menu, which
            // also fires our own adminmenu hook through Menu::insert().
            $tpl->addTemplatesFromModule('admin');
            $sspMenu = new SspAdminMenu();
            // Insert dispatches the adminmenu hooks; add logout afterwards so
            // hook-added entries still land before it, as on admin pages.
            $tpl = $sspMenu->insert($tpl);
            $sspMenu->addOption('logout', (new Auth())->getAdminLogoutURL(), Translate::noop('Log out'));
            $tpl->data['menu']['logout'] = [
                'url' => (new Auth())->getAdminLogoutURL(),
                'name' => Translate::noop('Log out'),
            ];
            $tpl->data['frontpage_section'] = 'authoauth2';
        }

        $tpl->data += $data;
        return $tpl;
    }
}
