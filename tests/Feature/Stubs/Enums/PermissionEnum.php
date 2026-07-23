<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs\Enums;

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
    case POSTS_CREATE = 'posts:create';
    case POSTS_DELETE = 'posts:delete';

    /**
     * Return the permission string.
     *
     * @return string
     */
    #[\Override]
    public function toString(): string
    {
        return $this->value;
    }
}
