<?php

declare(strict_types = 1);

namespace Tests\Unit\Events;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Events\Permission\Deprecated as PermissionDeprecated;
use SineMacula\Laravel\Authorization\Events\Permission\Reinstated as PermissionReinstated;
use SineMacula\Laravel\Authorization\Models\Permission;
use Tests\TestCase;

/**
 * Unit tests for the two permission lifecycle events introduced
 * alongside the sync command.
 *
 * Both events are promoted-parameter readonly value objects on the
 * SemVer-stable event API; each test pins the constructor-to-property
 * contract that audit listeners bind against.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(PermissionDeprecated::class)]
#[CoversClass(PermissionReinstated::class)]
final class PermissionDeprecatedReinstatedTest extends TestCase
{
    /**
     * `PermissionDeprecated` exposes the promoted `permission`
     * property.
     *
     * @return void
     */
    public function testDeprecatedExposesPermissionProperty(): void
    {
        $permission = new Permission(['name' => 'posts:delete']);

        $event = new PermissionDeprecated($permission);

        self::assertSame($permission, $event->permission);
    }

    /**
     * `PermissionReinstated` exposes the promoted `permission`
     * property.
     *
     * @return void
     */
    public function testReinstatedExposesPermissionProperty(): void
    {
        $permission = new Permission(['name' => 'posts:delete']);

        $event = new PermissionReinstated($permission);

        self::assertSame($permission, $event->permission);
    }
}
