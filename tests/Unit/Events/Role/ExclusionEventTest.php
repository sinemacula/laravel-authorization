<?php

declare(strict_types = 1);

namespace Tests\Unit\Events\Role;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Contracts\AuthorizationEvent;
use SineMacula\Laravel\Authorization\Contracts\AuthorizationMutation;
use SineMacula\Laravel\Authorization\Contracts\IdentityEvent;
use SineMacula\Laravel\Authorization\Events\Role\ExclusionDeclared;
use SineMacula\Laravel\Authorization\Events\Role\ExclusionEvent;
use SineMacula\Laravel\Authorization\Events\Role\ExclusionRemoved;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\AssertsAuditAccessors;

/**
 * Unit tests for what every change to a pair of mutually exclusive roles
 * carries.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ExclusionEvent::class)]
final class ExclusionEventTest extends TestCase
{
    use AssertsAuditAccessors;

    /**
     * The shared shape is an abstract readonly change event, never dispatched
     * itself and about no grantee, that the declared and removed events extend.
     *
     * @return void
     */
    public function testIsTheAbstractShapeBothEventsShare(): void
    {
        $reflection = new \ReflectionClass(ExclusionEvent::class);

        self::assertTrue($reflection->isAbstract());
        self::assertTrue($reflection->isReadOnly());
        self::assertTrue($reflection->implementsInterface(AuthorizationEvent::class));
        self::assertTrue($reflection->implementsInterface(AuthorizationMutation::class));
        self::assertFalse($reflection->implementsInterface(IdentityEvent::class));

        foreach ([ExclusionDeclared::class, ExclusionRemoved::class] as $class) {
            $parent = (new \ReflectionClass($class))->getParentClass();

            self::assertNotFalse($parent);
            self::assertSame(ExclusionEvent::class, $parent->getName());
        }
    }

    /**
     * Each event carries the operation, the pair's two roles and their names,
     * and the tenant that owns it, and is about the pair's first role.
     *
     * @return void
     */
    public function testCarriesTheOperationThePairAndItsOwner(): void
    {
        $operation = Operation::begin(new Reference('admin', '1'));
        $role      = new Reference('role', '1');
        $excluded  = new Reference('role', '2');
        $tenant    = self::tenant();

        foreach ([ExclusionDeclared::class, ExclusionRemoved::class] as $class) {
            $event = new $class($operation, $role, 'clerk', $excluded, 'auditor', $tenant);

            $carried = [$event->operation, $event->role, $event->roleName, $event->excludedRole, $event->excludedRoleName];

            self::assertSame([$operation, $role, 'clerk', $excluded, 'auditor'], $carried);
            self::assertSame($tenant, $event->tenant);
            self::assertSame($role, $event->subject());
        }
    }
}
