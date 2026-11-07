<?php

declare(strict_types = 1);

namespace Tests\Unit\Support;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Support\PrefetchedResourceTenants;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResourceReference;
use Tests\Feature\Stubs\FixedResourceTenantResolver;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Fixtures\BulkChecks\CountingBulkTenants;

/**
 * Unit tests for `PrefetchedResourceTenants`, the tenants of a bulk check's
 * resources read at once.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(PrefetchedResourceTenants::class)]
final class PrefetchedResourceTenantsTest extends TestCase
{
    /**
     * A bulk resolver is asked once for the models with a key and once for the
     * records of each type, each record once, and nothing else is asked about;
     * what it read is answered without asking again.
     *
     * @return void
     */
    public function testABulkResolverIsAskedOnceForEachKindOfResource(): void
    {
        $tenant   = new Reference('teams', '5');
        $resolver = new CountingBulkTenants(['1' => $tenant, '2' => null, '7' => $tenant]);
        $model    = new StubIdentity(['id' => '1']);
        $keyless  = new StubIdentity;
        $values   = [$model, $keyless, ['posts', '2'], ['posts', 2], ['notes', '7'], ['posts'], 'posts:3', null, ResourceReference::record('posts', '8')];
        $values[] = new StubIdentity(['id' => '1']);

        $tenants = PrefetchedResourceTenants::of($values, $resolver);

        self::assertSame([['1', '1'], ['2'], ['7']], $resolver->bulkCalls);
        self::assertSame($tenant, $tenants->tenantOf($model));
        self::assertNull($tenants->tenantOfRecord('posts', '2'));
        self::assertSame($tenant, $tenants->tenantOfRecord('notes', '7'));
        self::assertSame([], $resolver->calls);
    }

    /**
     * What was not read, every resource with a resolver that does not answer in
     * bulk included, is asked of the resolver on its own.
     *
     * @return void
     */
    public function testWhatWasNotReadIsAskedOnItsOwn(): void
    {
        $tenant   = new Reference('teams', '5');
        $resolver = new FixedResourceTenantResolver($tenant, false);
        $model    = new StubIdentity(['id' => '1']);
        $tenants  = PrefetchedResourceTenants::of([$model, ['posts', '2']], $resolver);

        self::assertSame([], $resolver->asked);
        self::assertSame($tenant, $tenants->tenantOf($model));
        self::assertFalse($tenants->tenantOfRecord('posts', '2'));
        self::assertSame([$model], $resolver->asked);
        self::assertSame([['posts', '2']], $resolver->askedRecords);

        $bulk    = new CountingBulkTenants(['1' => $tenant]);
        $tenants = PrefetchedResourceTenants::of([], $bulk);

        self::assertSame([], $bulk->bulkCalls);
        self::assertFalse($tenants->tenantOfRecord('posts', '9'));
        self::assertSame($tenant, $tenants->tenantOf($model));
        self::assertSame(['9', '1'], $bulk->calls);
    }

    /**
     * A bulk call that throws reads nothing, so each resource is asked about on
     * its own, and a record the answer leaves out is asked about on its own.
     *
     * @return void
     */
    public function testAFailedOrPartialBulkReadIsAskedOnItsOwn(): void
    {
        $tenant           = new Reference('teams', '5');
        $broken           = new CountingBulkTenants(['1' => $tenant, '2' => $tenant]);
        $broken->isBroken = true;
        $model            = new StubIdentity(['id' => '1']);
        $tenants          = PrefetchedResourceTenants::of([$model, ['posts', '2']], $broken);

        self::assertCount(2, $broken->bulkCalls);
        self::assertSame($tenant, $tenants->tenantOf($model));
        self::assertSame($tenant, $tenants->tenantOfRecord('posts', '2'));
        self::assertSame(['1', '2'], $broken->calls);

        $partial          = new CountingBulkTenants(['2' => $tenant, '3' => null]);
        $partial->failing = ['3'];
        $tenants          = PrefetchedResourceTenants::of([['posts', '2'], ['posts', '3']], $partial);

        self::assertSame($tenant, $tenants->tenantOfRecord('posts', '2'));
        self::assertSame([], $partial->calls);

        $this->expectException(\RuntimeException::class);

        $tenants->tenantOfRecord('posts', '3');
    }
}
