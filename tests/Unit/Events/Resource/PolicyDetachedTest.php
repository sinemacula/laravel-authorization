<?php

declare(strict_types = 1);

namespace Tests\Unit\Events\Resource;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Contracts\AuthorizationEvent;
use SineMacula\Laravel\Authorization\Events\Resource\PolicyDetached;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\AssertsAuditAccessors;

/**
 * Unit tests for the snapshot dispatched when a policy is detached from a
 * resource.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PolicyDetached::class)]
final class PolicyDetachedTest extends TestCase
{
    use AssertsAuditAccessors;

    /**
     * The event carries the operation, the resource, the policy, its name and
     * the scope, as plain values.
     *
     * @return void
     */
    public function testCarriesPlainValues(): void
    {
        $operation = Operation::begin();
        $policy    = new Reference('policy', 'policy-1');
        $scope     = new GrantScope(new Reference('stub_tenant', 'tenant-a'), 'admin', false);
        $event     = new PolicyDetached($operation, 'posts', '7', $policy, 'sharing', $scope);

        self::assertInstanceOf(AuthorizationEvent::class, $event);
        $carried = [$event->operation, $event->resourceType, $event->resourceId, $event->policy, $event->name, $event->scope];

        self::assertSame([$operation, 'posts', '7', $policy, 'sharing', $scope], $carried);
        self::assertNull((new PolicyDetached($operation, 'posts', null, $policy, 'sharing', GrantScope::platform()))->resourceId);
    }

    /**
     * The event about a whole resource type has no subject, and reports the
     * type, the policy, its name and its reach as plain details.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testDescribesTheChangeForAnAuditMapper(): void
    {
        $event = new PolicyDetached(Operation::begin(), 'posts', null, new Reference('policy', '9'), 'sharing', GrantScope::platform());

        self::assertDescribes($event, [
            'operation'   => 'resource.policy.detached',
            'subject'     => null,
            'tenant'      => null,
            'application' => null,
            'grantees'    => [],
            'properties'  => [
                'resource_type'         => 'posts',
                'resource_id'           => null,
                'policy'                => 'policy:9',
                'name'                  => 'sharing',
                'scope.include_subtree' => true,
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
        self::assertDescribesTheCall(static fn (Operation $operation): PolicyDetached => new PolicyDetached(
            $operation,
            'posts',
            null,
            new Reference('policy', '9'),
            'sharing',
            GrantScope::platform(),
        ));
    }
}
