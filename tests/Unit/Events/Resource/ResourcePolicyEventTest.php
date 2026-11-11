<?php

declare(strict_types = 1);

namespace Tests\Unit\Events\Resource;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Contracts\AuthorizationEvent;
use SineMacula\Laravel\Authorization\Contracts\AuthorizationMutation;
use SineMacula\Laravel\Authorization\Events\Resource\PolicyAttached;
use SineMacula\Laravel\Authorization\Events\Resource\PolicyDetached;
use SineMacula\Laravel\Authorization\Events\Resource\ResourcePolicyEvent;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Unit tests for what every change to a resource policy attachment carries.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ResourcePolicyEvent::class)]
final class ResourcePolicyEventTest extends TestCase
{
    /**
     * The shared shape is an abstract readonly event, never dispatched itself,
     * that the attached and detached events extend unchanged.
     *
     * @return void
     */
    public function testIsTheAbstractShapeBothEventsShare(): void
    {
        $reflection = new \ReflectionClass(ResourcePolicyEvent::class);

        self::assertTrue($reflection->isAbstract());
        self::assertTrue($reflection->isReadOnly());
        self::assertTrue($reflection->implementsInterface(AuthorizationEvent::class));
        self::assertTrue($reflection->implementsInterface(AuthorizationMutation::class));

        foreach ([PolicyAttached::class, PolicyDetached::class] as $class) {
            $parent = (new \ReflectionClass($class))->getParentClass();

            self::assertNotFalse($parent);
            self::assertSame(ResourcePolicyEvent::class, $parent->getName());
        }
    }

    /**
     * Each event carries the operation, the resource's type and key, the
     * policy, its name and the scope, in that order.
     *
     * @return void
     */
    public function testCarriesTheOperationResourcePolicyNameAndScope(): void
    {
        $operation = Operation::begin();
        $policy    = new Reference('policy', 'policy-1');
        $scope     = GrantScope::platform();

        foreach ([new PolicyAttached($operation, 'posts', null, $policy, 'sharing', $scope), new PolicyDetached($operation, 'posts', '7', $policy, 'sharing', $scope)] as $event) {
            self::assertSame([$operation, 'posts', $policy, 'sharing', $scope], [$event->operation, $event->resourceType, $event->policy, $event->name, $event->scope]);
        }

        $constructor = new \ReflectionMethod(ResourcePolicyEvent::class, '__construct');
        $parameters  = \array_map(static fn (\ReflectionParameter $parameter): string => $parameter->getName(), $constructor->getParameters());

        self::assertSame(['operation', 'resourceType', 'resourceId', 'policy', 'name', 'scope'], $parameters);
    }

    /**
     * Each event is about the record the policy is attached to, or about no
     * record for a whole resource type, holds in its scope's tenant and
     * application, names no grantee and reports the rest as plain details.
     *
     * @return void
     */
    public function testDescribesTheAttachmentForAnAuditMapper(): void
    {
        $tenant = new Reference('team', '7');
        $record = new PolicyAttached(Operation::begin(), 'posts', '7', new Reference('policy', '9'), 'sharing', new GrantScope($tenant, 'admin', false));
        $type   = new PolicyDetached(Operation::begin(), 'posts', null, new Reference('policy', '9'), 'sharing', GrantScope::platform());

        self::assertEquals(new Reference('posts', '7'), $record->subject());
        self::assertSame($tenant, $record->tenant());
        self::assertSame('admin', $record->application());
        self::assertSame([], $record->grantees());
        self::assertSame([
            'resource_type'         => 'posts',
            'resource_id'           => '7',
            'policy'                => 'policy:9',
            'name'                  => 'sharing',
            'scope.include_subtree' => false,
        ], $record->auditProperties());
        self::assertNull($type->subject());
        self::assertNull($type->tenant());
        self::assertNull($type->application());
    }
}
