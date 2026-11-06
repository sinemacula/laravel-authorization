<?php

declare(strict_types = 1);

namespace Tests\Unit\Events\Identity;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Contracts\IdentityEvent;
use SineMacula\Laravel\Authorization\Events\Identity\BoundaryRemoved;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Unit tests for the snapshot dispatched when a grantee's permission boundary
 * is removed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(BoundaryRemoved::class)]
final class BoundaryRemovedTest extends TestCase
{
    /**
     * The event carries the operation, the grantee, the policy, its name and
     * the scope, as plain values.
     *
     * @return void
     */
    public function testCarriesPlainValues(): void
    {
        $operation = Operation::begin();
        $grantee   = new Reference('user', 'user-1');
        $policy    = new Reference('policy', 'policy-1');
        $scope     = new GrantScope(new Reference('stub_tenant', 'tenant-a'));
        $event     = new BoundaryRemoved($operation, $grantee, $policy, 'cap', $scope);

        self::assertInstanceOf(IdentityEvent::class, $event);
        self::assertSame([$operation, $grantee, $policy, 'cap', $scope], [$event->operation, $event->grantee, $event->policy, $event->name, $event->scope]);
    }
}
