<?php

declare(strict_types = 1);

namespace Tests\Unit\Events\Concerns;

use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Events\Concerns\DescribesGrantChange;
use SineMacula\Laravel\Authorization\Events\Identity\BoundaryRemoved;
use SineMacula\Laravel\Authorization\Events\Identity\PermissionRevoked;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\AssertsAuditAccessors;

/**
 * Unit tests for the audit accessors the grant and boundary events share.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversTrait(DescribesGrantChange::class)]
final class DescribesGrantChangeTest extends TestCase
{
    use AssertsAuditAccessors;

    /**
     * The grantee is the subject and the one grantee, and the scope's tenant
     * and application are where the change holds.
     *
     * @return void
     */
    public function testDescribesTheGranteeAndTheScope(): void
    {
        $grantee = new Reference('user', '42');
        $tenant  = new Reference('team', '7');
        $event   = new PermissionRevoked(Operation::begin(), $grantee, new Reference('permission', '5'), 'posts.update', new GrantScope($tenant, 'admin'));

        self::assertSame($grantee, $event->subject());
        self::assertSame($tenant, $event->tenant());
        self::assertSame('admin', $event->application());
        self::assertSame([$grantee], $event->grantees());
        self::assertSame(['permission' => 'permission:5', 'name' => 'posts.update', 'scope.include_subtree' => true], $event->auditProperties());
    }

    /**
     * A platform-wide change, a boundary's among them, holds in no tenant and
     * in every application.
     *
     * @return void
     */
    public function testDescribesAPlatformWideChange(): void
    {
        $grantee = new Reference('user', '42');
        $event   = new BoundaryRemoved(Operation::begin(), $grantee, new Reference('policy', '9'), 'cap', GrantScope::platform());

        self::assertSame($grantee, $event->subject());
        self::assertNull($event->tenant());
        self::assertNull($event->application());
        self::assertSame([$grantee], $event->grantees());
        self::assertSame(['policy' => 'policy:9', 'name' => 'cap', 'scope.include_subtree' => true], $event->auditProperties());
    }

    /**
     * A grant or boundary event reports the call that made the change, trusted
     * or delegated, with or without an impersonator, and never its client.
     *
     * @return void
     */
    public function testDescribesTheCallForAnAuditMapper(): void
    {
        self::assertDescribesTheCall(static fn (Operation $operation): PermissionRevoked => new PermissionRevoked(
            $operation,
            self::grantee(),
            new Reference('permission', '5'),
            'posts.update',
            self::scope(),
        ));
    }
}
