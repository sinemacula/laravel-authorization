<?php

declare(strict_types = 1);

namespace Tests\Unit\Events\Identity;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Contracts\IdentityEvent;
use SineMacula\Laravel\Authorization\Events\Identity\BoundaryEvent;
use SineMacula\Laravel\Authorization\Events\Identity\BoundaryRemoved;
use SineMacula\Laravel\Authorization\Events\Identity\BoundarySet;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Unit tests for what every change to a grantee's permission boundary carries.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(BoundaryEvent::class)]
final class BoundaryEventTest extends TestCase
{
    /**
     * The shared shape is an abstract readonly grant event, never dispatched
     * itself, that the set and removed events extend.
     *
     * @return void
     */
    public function testIsTheAbstractShapeBothEventsShare(): void
    {
        $reflection = new \ReflectionClass(BoundaryEvent::class);

        self::assertTrue($reflection->isAbstract());
        self::assertTrue($reflection->isReadOnly());
        self::assertTrue($reflection->implementsInterface(IdentityEvent::class));

        foreach ([BoundarySet::class, BoundaryRemoved::class] as $class) {
            $parent = (new \ReflectionClass($class))->getParentClass();

            self::assertNotFalse($parent);
            self::assertSame(BoundaryEvent::class, $parent->getName());
        }
    }

    /**
     * Each event carries the operation, the grantee, the policy, its name and
     * the scope.
     *
     * @return void
     */
    public function testCarriesTheOperationGranteePolicyNameAndScope(): void
    {
        $operation = Operation::begin();
        $grantee   = new Reference('user', 'user-1');
        $policy    = new Reference('policy', 'policy-1');
        $scope     = new GrantScope(new Reference('stub_tenant', 'tenant-a'), null, false);

        foreach ([new BoundarySet($operation, $grantee, $policy, 'cap', $scope), new BoundaryRemoved($operation, $grantee, $policy, 'cap', $scope)] as $event) {
            self::assertSame([$operation, $grantee, $policy, 'cap', $scope], [$event->operation, $event->grantee, $event->policy, $event->name, $event->scope]);
        }
    }
}
