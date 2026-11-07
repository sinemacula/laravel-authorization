<?php

declare(strict_types = 1);

namespace Tests\Feature\Resolvers;

use Illuminate\Database\Eloquent\Relations\Relation;
use Illuminate\Database\Query\Builder as QueryBuilder;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\After;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Contracts\ResourceTenantResolver;
use SineMacula\Laravel\Authorization\Resolvers\DeclaredResourceTenant;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResourceReference;
use SineMacula\Laravel\Authorization\Support\ResourceReferences;
use Tests\Feature\Stubs\FixedResourceTenantResolver;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Fixtures\QueryRecorder;
use Tests\Fixtures\QueryScoping\RecordedTenantPost;
use Tests\Fixtures\QueryScoping\ScopedPost;
use Tests\Fixtures\QueryScoping\ScopedTicket;
use Tests\Fixtures\QueryScoping\TenantScopedDocument;
use Tests\Fixtures\QueryScoping\TenantScopedPost;
use Tests\Fixtures\QueryScoping\UuidScopedDocument;
use Tests\TestCase;

/**
 * Feature tests for the resource tenant resolver the package binds, which
 * answers a model that declares its tenancy from its declaration and every
 * other through the configured resolver.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DeclaredResourceTenant::class)]
final class DeclaredResourceTenantTest extends TestCase
{
    /**
     * A declared model's tenant is read from its declaration, raw, without
     * asking the configured resolver; any other model's is the configured
     * resolver's.
     *
     * @return void
     */
    public function testADeclaredModelIsAnsweredFromItsDeclaration(): void
    {
        $fallback = new FixedResourceTenantResolver(new Reference('fixed', '1'));
        $resolver = new DeclaredResourceTenant($fallback);
        $post     = TenantScopedPost::query()->create(['tenant_type' => 'teams', 'tenant_id' => '5']);
        $other    = StubIdentity::create(['id' => 'u1']);

        self::assertEquals(new Reference('teams', '5'), $resolver->tenantOf($post));
        self::assertNull($resolver->tenantOf(new ScopedPost));
        self::assertEquals(new Reference('fixed', '1'), $resolver->tenantOf($other));
        self::assertSame([$other], $fallback->asked);
    }

    /**
     * A pair naming a declared model, by its class or through the morph map, is
     * answered from its record's tenant columns: none for a tenantless model,
     * the record's tenant, or false for a record that does not exist or a key
     * that is not an integer for an integer-keyed model. A pair naming any
     * other type is the configured resolver's.
     *
     * @return void
     */
    public function testAPairNamingADeclaredModelLooksItsRecordUp(): void
    {
        $fallback = new FixedResourceTenantResolver(null, false);
        $resolver = new DeclaredResourceTenant($fallback);
        $ticket   = ScopedTicket::query()->create(['team_id' => 9]);

        Relation::morphMap(['tickets' => ScopedTicket::class]);

        self::assertNull($resolver->tenantOfRecord(ScopedPost::class, '1'));
        self::assertEquals(new Reference('teams', '9'), $resolver->tenantOfRecord(ScopedTicket::class, (string) $ticket->getKey())); // @phpstan-ignore cast.string
        self::assertEquals(new Reference('teams', '9'), $resolver->tenantOfRecord('tickets', (string) $ticket->getKey())); // @phpstan-ignore cast.string
        self::assertFalse($resolver->tenantOfRecord(ScopedTicket::class, '999'));
        self::assertFalse($resolver->tenantOfRecord(ScopedTicket::class, 'abc'));
        self::assertFalse($resolver->tenantOfRecord(ScopedTicket::class, \str_repeat('9', 19)));
        self::assertFalse($resolver->tenantOfRecord(ScopedTicket::class, \str_repeat('9', 11)));
        self::assertFalse($resolver->tenantOfRecord('posts', '1'));
        self::assertFalse($resolver->tenantOfRecord(StubIdentity::class, 'u1'));
        self::assertSame([['posts', '1'], [StubIdentity::class, 'u1']], $fallback->askedRecords);
    }

    /**
     * A pair naming a string-keyed declared model is looked up whatever its
     * key, a long run of digits included, which bounds only an integer key.
     *
     * @return void
     */
    public function testAPairNamingAStringKeyedModelLooksItsRecordUp(): void
    {
        $resolver = new DeclaredResourceTenant(new FixedResourceTenantResolver(null, false));
        $digits   = \str_repeat('9', 19);

        TenantScopedDocument::query()->create(['code' => 'doc-a', 'tenant_type' => 'teams', 'tenant_id' => 't1']);
        TenantScopedDocument::query()->create(['code' => $digits, 'tenant_type' => 'teams', 'tenant_id' => 't2']);

        self::assertEquals(new Reference('teams', 't1'), $resolver->tenantOfRecord(TenantScopedDocument::class, 'doc-a'));
        self::assertEquals(new Reference('teams', 't2'), $resolver->tenantOfRecord(TenantScopedDocument::class, $digits));
        self::assertFalse($resolver->tenantOfRecord(TenantScopedDocument::class, 'missing-doc'));
    }

    /**
     * A key the key column could not hold names no record, so it is never
     * looked up: a uuid column's key that is not a uuid, and one that is not
     * UTF-8, deny inside a transaction that stays usable, on PostgreSQL too.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAKeyTheColumnCannotHoldNamesNoRecord(): void
    {
        $resolver = new DeclaredResourceTenant(new FixedResourceTenantResolver(null, false));
        $id       = (string) Str::uuid();
        $isSqlite = DB::connection()->getDriverName() === 'sqlite';

        UuidScopedDocument::query()->create(['id' => $id, 'tenant_type' => 'teams', 'tenant_id' => 't1']);

        // SQLite keeps any bytes, and is asked for them.
        if ($isSqlite) {
            UuidScopedDocument::query()->create(['id' => "\xff\xfe", 'tenant_type' => 'teams', 'tenant_id' => 't2']);
        }

        DB::transaction(static function () use ($resolver, $id, $isSqlite): void {
            self::assertFalse($resolver->tenantOfRecord(UuidScopedDocument::class, 'not-a-uuid'));
            self::assertEquals($isSqlite ? new Reference('teams', 't2') : false, $resolver->tenantOfRecord(UuidScopedDocument::class, "\xff\xfe"));
            self::assertEquals(new Reference('teams', 't1'), $resolver->tenantOfRecord(UuidScopedDocument::class, $id));
            self::assertSame($isSqlite ? 2 : 1, UuidScopedDocument::query()->count());
        });

        self::assertFalse(ResourceReferences::of([UuidScopedDocument::class, 'not-a-uuid']));
    }

    /**
     * The record is looked up on the write connection, so a record just moved
     * to another tenant is read as it is now.
     *
     * @return void
     */
    public function testThePairsRecordIsReadOnTheWriteConnection(): void
    {
        $post = RecordedTenantPost::query()->create(['tenant_type' => 'teams', 'tenant_id' => '5']);

        QueryRecorder::reset();

        $resolver = new DeclaredResourceTenant(new FixedResourceTenantResolver);

        self::assertEquals(new Reference('teams', '5'), $resolver->tenantOfRecord(RecordedTenantPost::class, (string) $post->getKey())); // @phpstan-ignore cast.string

        $lookups = \array_values(\array_filter(QueryRecorder::recorded(), static fn (QueryBuilder $query): bool => $query->wheres !== []));

        self::assertCount(1, $lookups);
        self::assertTrue($lookups[0]->useWritePdo);
    }

    /**
     * The service provider binds the declared resolver around the configured
     * one, so `check()` reads a declared model's tenant from its declaration.
     *
     * @return void
     */
    public function testTheBoundResolverReadsTheDeclaration(): void
    {
        $post      = TenantScopedPost::query()->create(['tenant_type' => 'teams', 'tenant_id' => '5']);
        $reference = ResourceReferences::of($post);

        self::assertInstanceOf(DeclaredResourceTenant::class, $this->app?->make(ResourceTenantResolver::class));
        self::assertInstanceOf(ResourceReference::class, $reference);
        self::assertEquals(new Reference('teams', '5'), $reference->tenant);
    }

    /**
     * Forget the morph map a test set.
     *
     * @return void
     */
    #[After]
    protected function forgetMorphMap(): void
    {
        Relation::morphMap([], false);
    }
}
