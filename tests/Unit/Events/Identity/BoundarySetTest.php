<?php

declare(strict_types = 1);

namespace Tests\Unit\Events\Identity;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Contracts\IdentityEvent;
use SineMacula\Laravel\Authorization\Events\Identity\BoundarySet;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\AssertsAuditAccessors;

/**
 * Unit tests for the snapshot dispatched when a policy is set as a grantee's
 * permission boundary.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(BoundarySet::class)]
final class BoundarySetTest extends TestCase
{
    use AssertsAuditAccessors;

    /**
     * The event carries the operation, the grantee, the policy, its name, the
     * scope and the policy it replaced, as plain values; a new boundary
     * replaced none.
     *
     * @return void
     */
    public function testCarriesPlainValues(): void
    {
        $operation = Operation::begin();
        $grantee   = new Reference('user', 'user-1');
        $policy    = new Reference('policy', 'policy-2');
        $previous  = new Reference('policy', 'policy-1');
        $event     = new BoundarySet($operation, $grantee, $policy, 'cap', GrantScope::platform(), $previous);

        self::assertInstanceOf(IdentityEvent::class, $event);
        self::assertSame([$operation, $grantee, $policy, 'cap', $previous], [$event->operation, $event->grantee, $event->policy, $event->name, $event->previous]);
        self::assertEquals(GrantScope::platform(), $event->scope);
        self::assertNull((new BoundarySet($operation, $grantee, $policy, 'cap', GrantScope::platform()))->previous);
    }

    /**
     * The event is about its grantee, holds in its scope's tenant, and reports
     * the policy, its name, its reach and the policy it replaced as plain
     * details.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testDescribesTheChangeForAnAuditMapper(): void
    {
        $grantee = self::grantee();
        $event   = new BoundarySet(Operation::begin(), $grantee, new Reference('policy', '9'), 'cap', new GrantScope(self::tenant(), null, false), new Reference('policy', '8'));

        self::assertDescribes($event, [
            'operation'   => 'identity.boundary.set',
            'subject'     => $grantee,
            'tenant'      => self::tenant(),
            'application' => null,
            'grantees'    => [$grantee],
            'properties'  => [
                'policy'                => 'policy:9',
                'name'                  => 'cap',
                'scope.include_subtree' => false,
                'previous'              => 'policy:8',
            ],
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
        self::assertDescribesTheCall(static fn (Operation $operation): BoundarySet => new BoundarySet(
            $operation,
            self::grantee(),
            new Reference('policy', '9'),
            'cap',
            new GrantScope(self::tenant(), null, false),
            new Reference('policy', '8'),
        ));
    }
}
