<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use SineMacula\Laravel\Authorization\Contracts\PermissionEnum as PermissionEnumContract;

/**
 * Demo permission enum used to exercise Gate auto-wiring in tests.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
enum PermissionEnum: string implements PermissionEnumContract
{
    case PostsCreate = 'posts:create';
    case PostsDelete = 'posts:delete';

    /**
     * Return the permission string.
     *
     * @return string
     */
    public function toString(): string
    {
        return $this->value;
    }
}
