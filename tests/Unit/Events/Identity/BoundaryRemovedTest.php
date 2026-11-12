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
use Tests\Concerns\AssertsAuditAccessors;

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
    use AssertsAuditAccessors;

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

    /**
     * The event is about its grantee, holds in its scope's tenant, and reports
     * the policy, its name and its reach as plain details.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testDescribesTheChangeForAnAuditMapper(): void
    {
        $grantee = self::grantee();
        $event   = new BoundaryRemoved(Operation::begin(), $grantee, new Reference('policy', '9'), 'cap', new GrantScope(self::tenant(), null, false));

        self::assertDescribes($event, [
            'operation'   => 'identity.boundary.removed',
            'subject'     => $grantee,
            'tenant'      => self::tenant(),
            'application' => null,
            'grantees'    => [$grantee],
            'properties'  => ['policy' => 'policy:9', 'name' => 'cap', 'scope.include_subtree' => false],
        ]);
    }

    /**
     * The event reports the call that made the change, trusted or delegated,
     * with or without an impersonator, and never its client.
     *
     * @return void
     */
    public function testDescribesTheCallForAnAuditMapper(): void
    {
        self::assertDescribesTheCall(static fn (Operation $operation): BoundaryRemoved => new BoundaryRemoved(
            $operation,
            self::grantee(),
            new Reference('policy', '9'),
            'cap',
            new GrantScope(self::tenant(), null, false),
        ));
    }
}
