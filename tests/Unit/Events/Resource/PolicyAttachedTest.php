<?php

declare(strict_types = 1);

namespace Tests\Unit\Events\Resource;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Contracts\AuthorizationEvent;
use SineMacula\Laravel\Authorization\Events\Resource\PolicyAttached;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\AssertsAuditAccessors;

/**
 * Unit tests for the snapshot dispatched when a policy is attached to a
 * resource.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PolicyAttached::class)]
final class PolicyAttachedTest extends TestCase
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
        $event     = new PolicyAttached($operation, 'posts', '7', $policy, 'sharing', $scope);

        self::assertInstanceOf(AuthorizationEvent::class, $event);
        $carried = [$event->operation, $event->resourceType, $event->resourceId, $event->policy, $event->name, $event->scope];

        self::assertSame([$operation, 'posts', '7', $policy, 'sharing', $scope], $carried);
        self::assertNull((new PolicyAttached($operation, 'posts', null, $policy, 'sharing', GrantScope::platform()))->resourceId);
    }

    /**
     * The event is about the record the policy is attached to, holds in its
     * scope's tenant and application, names no grantee, and reports the
     * resource, the policy, its name and its reach as plain details.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testDescribesTheChangeForAnAuditMapper(): void
    {
        $event = new PolicyAttached(Operation::begin(), 'posts', '7', new Reference('policy', '9'), 'sharing', self::scope());

        self::assertDescribes($event, [
            'operation'   => 'resource.policy.attached',
            'subject'     => new Reference('posts', '7'),
            'tenant'      => self::tenant(),
            'application' => 'admin',
            'grantees'    => [],
            'properties'  => [
                'resource_type'         => 'posts',
                'resource_id'           => '7',
                'policy'                => 'policy:9',
                'name'                  => 'sharing',
                'scope.include_subtree' => false,
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
        self::assertDescribesTheCall(static fn (Operation $operation): PolicyAttached => new PolicyAttached(
            $operation,
            'posts',
            '7',
            new Reference('policy', '9'),
            'sharing',
            self::scope(),
        ));
    }
}
