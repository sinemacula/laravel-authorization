<?php

declare(strict_types = 1);

namespace Tests\Feature\Resolvers;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
use SineMacula\Laravel\Authorization\Resolvers\FlatTenantTree;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\TestCase;

/**
 * Feature tests for the default, flat tenant tree.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FlatTenantTree::class)]
final class FlatTenantTreeTest extends TestCase
{
    /**
     * No tenant has an ancestor, and a tenant is within only itself.
     *
     * @return void
     */
    public function testATenantIsWithinOnlyItself(): void
    {
        $tree   = new FlatTenantTree;
        $tenant = new Reference('stub_tenant', '1');

        self::assertSame([], $tree->ancestors($tenant));
        self::assertTrue($tree->isWithin($tenant, new Reference('stub_tenant', '1')));
        self::assertFalse($tree->isWithin($tenant, new Reference('stub_tenant', '2')));
        self::assertFalse($tree->isWithin($tenant, new Reference('stub_org', '1')));
    }

    /**
     * A tenant's subtree is the tenant alone, as a query on the package's
     * connection.
     *
     * @return void
     */
    public function testTheSubtreeIsTheTenantAlone(): void
    {
        $query = (new FlatTenantTree)->subtree(new Reference('stub_tenant', 'tenant-a'));

        self::assertSame(AuthorizationConnection::connection(), $query->getConnection()); // @phpstan-ignore method.notFound
        self::assertEquals([['tenant_type' => 'stub_tenant', 'tenant_id' => 'tenant-a']], $query->get()->map(static fn (object $row): array => (array) $row)->all());
    }
}
