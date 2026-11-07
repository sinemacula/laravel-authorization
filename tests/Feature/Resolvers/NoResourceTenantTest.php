<?php

declare(strict_types = 1);

namespace Tests\Feature\Resolvers;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Contracts\ResourceTenantResolver;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Resolvers\DeclaredResourceTenant;
use SineMacula\Laravel\Authorization\Resolvers\NoResourceTenant;
use SineMacula\Laravel\Authorization\Support\ResourceReference;
use SineMacula\Laravel\Authorization\Support\ResourceReferences;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubTenant;
use Tests\TestCase;

/**
 * Feature tests for the default resource tenant resolver, which knows no
 * model's or record's tenant.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(NoResourceTenant::class)]
final class NoResourceTenantTest extends TestCase
{
    /**
     * No model has a tenant, its tenant columns included, which are not read.
     *
     * @return void
     */
    public function testKnowsNoModelsTenant(): void
    {
        $resolver = new NoResourceTenant;
        $owned    = (new StubTenant)->forceFill(['id' => 'record-1', 'tenant_type' => 'stub_tenant', 'tenant_id' => 'tenant-a']);

        self::assertNull($resolver->tenantOf(StubTenant::query()->create(['id' => 'tenant-a', 'name' => 'Tenant A'])));
        self::assertNull($resolver->tenantOf($owned));
        self::assertNull($resolver->tenantOf(new StubTenant));
    }

    /**
     * No `(type, id)` pair's record has a tenant either, whatever it names, a
     * tenant itself included, and none is refused as one it cannot tell.
     *
     * @return void
     */
    public function testKnowsNoRecordsTenant(): void
    {
        $resolver = new NoResourceTenant;

        StubTenant::query()->create(['id' => 'tenant-a', 'name' => 'Tenant A']);

        self::assertNull($resolver->tenantOfRecord('post', '42'));
        self::assertNull($resolver->tenantOfRecord(StubTenant::class, 'tenant-a'));
        self::assertNull($resolver->tenantOfRecord('post', 'missing'));
    }

    /**
     * Under the default, a pair's reference carries no tenant, so a check on it
     * with no tenant active is decided where the request is.
     *
     * @return void
     */
    public function testAPairIsDecidedWhereTheRequestIs(): void
    {
        $user = StubIdentity::create(['id' => (string) Str::uuid()]);

        $user->attachPolicy(Policy::create([
            'id'       => (string) Str::uuid(),
            'name'     => 'every-post',
            'document' => [
                'statements' => [
                    ['effect' => 'allow', 'actions' => ['posts:update'], 'resources' => ['post:*']],
                ],
            ],
        ]));

        $reference = ResourceReferences::of(['post', 42]);

        self::assertEquals(ResourceReference::record('post', '42'), $reference);
        self::assertTrue(Authorization::for($user)->check('posts:update', ['post', 42])->isAllowed());
    }

    /**
     * It is the configured resolver, which the bound declared resolver answers
     * every undeclared model through, until the application binds its own, the
     * same one for the whole request.
     *
     * @return void
     */
    public function testIsTheDefaultResolver(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app?->make(ConfigRepository::class);

        self::assertSame(NoResourceTenant::class, $config->get('authorization.resource_tenant_resolver'));
        self::assertInstanceOf(DeclaredResourceTenant::class, $this->app?->make(ResourceTenantResolver::class));
        self::assertInstanceOf(NoResourceTenant::class, (fn (): ResourceTenantResolver => $this->fallback)->call($this->app->make(ResourceTenantResolver::class)));
        self::assertSame($this->app->make(ResourceTenantResolver::class), $this->app->make(ResourceTenantResolver::class));
    }

    /**
     * Under the default, a saved model's reference carries no tenant, so a
     * check on it with no tenant active is decided where the request is rather
     * than refused as out of scope.
     *
     * @return void
     */
    public function testAModelIsDecidedWhereTheRequestIs(): void
    {
        $user  = StubIdentity::create(['id' => (string) Str::uuid()]);
        $model = StubTenant::query()->create(['id' => 'tenant-a', 'name' => 'Tenant A']);

        $user->attachPolicy(Policy::create([
            'id'       => (string) Str::uuid(),
            'name'     => 'every-tenant-record',
            'document' => [
                'statements' => [
                    ['effect' => 'allow', 'actions' => ['posts:update'], 'resources' => [StubTenant::class . ':*']],
                ],
            ],
        ]));

        $reference = ResourceReferences::of($model);
        $decision  = Authorization::for($user)->check('posts:update', $model);

        self::assertInstanceOf(ResourceReference::class, $reference);
        self::assertNull($reference->tenant);
        self::assertTrue($decision->isAllowed());
        self::assertNotSame(DecisionReason::TENANT_SCOPE, $decision->reason);
    }

    /**
     * In bulk, no model and no record has a tenant, each keyed as given.
     *
     * @return void
     */
    public function testNoResourceHasATenantInBulk(): void
    {
        $resolver = new NoResourceTenant;
        $models   = ['a' => new StubTenant(['id' => 't1']), 4 => new StubIdentity(['id' => 'u1'])];

        self::assertSame(['a' => null, 4 => null], $resolver->tenantsOf($models));
        self::assertSame(['x' => null, 2 => null], $resolver->tenantsOfRecords('posts', ['x' => '1', 2 => '9']));
        self::assertSame([], $resolver->tenantsOf([]));
        self::assertSame([], $resolver->tenantsOfRecords('posts', []));
    }
}
