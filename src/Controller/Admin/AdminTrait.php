<?php

declare(strict_types=1);

namespace SimpleSAML\Module\authoauth2\Controller\Admin;

use SimpleSAML\Utils\Auth;

/**
 * Guards the admin federation pages with SSP's admin authentication.
 */
trait AdminTrait
{
    protected function requireAdmin(): void
    {
        (new Auth())->requireAdmin();
    }
}
