<?php

declare(strict_types = 1);

namespace Tests\Unit\Events\Guardrail;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Contracts\AuthorizationEvent;
use SineMacula\Laravel\Authorization\Contracts\AuthorizationMutation;
use SineMacula\Laravel\Authorization\Contracts\IdentityEvent;
use SineMacula\Laravel\Authorization\Events\Guardrail\GuardrailEvent;
use SineMacula\Laravel\Authorization\Events\Guardrail\GuardrailRemoved;
use SineMacula\Laravel\Authorization\Events\Guardrail\GuardrailSet;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\AssertsAuditAccessors;

/**
 * Unit tests for what every change to a guardrail carries.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(GuardrailEvent::class)]
final class GuardrailEventTest extends TestCase
{
    use AssertsAuditAccessors;

    /**
     * The shared shape is an abstract readonly authorization event, never
     * dispatched itself and about no grantee, that the set and removed events
     * extend.
     *
     * @return void
     */
    public function testIsTheAbstractShapeBothEventsShare(): void
    {
        $reflection = new \ReflectionClass(GuardrailEvent::class);

        self::assertTrue($reflection->isAbstract());
        self::assertTrue($reflection->isReadOnly());
        self::assertTrue($reflection->implementsInterface(AuthorizationEvent::class));
        self::assertTrue($reflection->implementsInterface(AuthorizationMutation::class));
        self::assertFalse($reflection->implementsInterface(IdentityEvent::class));

        foreach ([GuardrailSet::class, GuardrailRemoved::class] as $class) {
            $parent = (new \ReflectionClass($class))->getParentClass();

            self::assertNotFalse($parent);
            self::assertSame(GuardrailEvent::class, $parent->getName());
        }
    }

    /**
     * Each event carries the operation, the policy, its name and the scope.
     *
     * @return void
     */
    public function testCarriesTheOperationPolicyNameAndScope(): void
    {
        $operation = Operation::begin(new Reference('admin', '1'));
        $policy    = new Reference('policy', 'policy-1');
        $scope     = new GrantScope(new Reference('stub_tenant', 'tenant-a'));

        foreach ([new GuardrailSet($operation, $policy, 'cap', $scope), new GuardrailRemoved($operation, $policy, 'cap', $scope)] as $event) {
            self::assertSame([$operation, $policy, 'cap', $scope], [$event->operation, $event->policy, $event->name, $event->scope]);
        }
    }

    /**
     * Each event is about the tenant whose guardrails changed, or about none on
     * the platform, holds there in every application, names no grantee and
     * reports the rest as plain details.
     *
     * @return void
     */
    public function testDescribesTheGuardrailForAnAuditMapper(): void
    {
        $tenant   = new Reference('team', '7');
        $tenanted = new GuardrailSet(Operation::begin(), new Reference('policy', '9'), 'cap', new GrantScope($tenant, 'admin'));
        $platform = new GuardrailRemoved(Operation::begin(), new Reference('policy', '9'), 'cap', GrantScope::platform());

        self::assertSame($tenant, $tenanted->subject());
        self::assertSame($tenant, $tenanted->tenant());
        self::assertNull($tenanted->application());
        self::assertSame([], $tenanted->grantees());
        self::assertSame(['policy' => 'policy:9', 'name' => 'cap', 'scope.include_subtree' => true], $tenanted->auditProperties());
        self::assertNull($platform->subject());
        self::assertNull($platform->tenant());
    }

    /**
     * Each event reports the call that made the change, trusted or delegated,
     * with or without an impersonator, and never its client.
     *
     * @return void
     */
    public function testDescribesTheCallForAnAuditMapper(): void
    {
        $policy = new Reference('policy', '9');

        self::assertDescribesTheCall(static fn (Operation $operation): GuardrailSet => new GuardrailSet($operation, $policy, 'cap', GrantScope::platform()));
        self::assertDescribesTheCall(static fn (Operation $operation): GuardrailRemoved => new GuardrailRemoved($operation, $policy, 'cap', GrantScope::platform()));
    }
}
