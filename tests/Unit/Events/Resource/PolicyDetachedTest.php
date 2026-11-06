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
}
