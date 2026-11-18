<?php

declare(strict_types = 1);

namespace Tests\Feature\Resolvers;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\Relation;
use Illuminate\Database\Query\Builder as QueryBuilder;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\SQLiteConnection;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\After;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Contracts\ResourceTenantResolver;
use SineMacula\Laravel\Authorization\Evaluation\CheckInput;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Resolvers\DeclaredResourceTenant;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResourceReference;
use SineMacula\Laravel\Authorization\Support\ResourceReferences;
use Tests\Concerns\ScopesQueries;
use Tests\Feature\Stubs\FixedResourceTenantResolver;
use Tests\Feature\Stubs\StubGrantee;
use Tests\Fixtures\BulkChecks\CountingBulkTenants;
use Tests\Fixtures\BulkChecks\UnreadableTenantPost;
use Tests\Fixtures\QueryRecorder;
use Tests\Fixtures\QueryScoping\IntegerTypedPost;
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
    use ScopesQueries;

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
        $other    = StubGrantee::create(['id' => 'u1']);

        self::assertEquals(new Reference('teams', '5'), $resolver->tenantOf($post));
        self::assertNull($resolver->tenantOf(new ScopedPost));
        self::assertEquals(new Reference('fixed', '1'), $resolver->tenantOf($other));
        self::assertSame([$other], $fallback->asked);
    }

    /**
     * A pair naming a declared model, by its class or through the morph map, is
     * answered from its record's tenant columns: none for a tenantless model,
     * the record's tenant, or false for a record that does not exist or a key
     * that is not an integer's canonical text within 64 bits for an
     * integer-keyed model, tenantless or not. A pair naming any other type is
     * the configured resolver's.
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
        self::assertFalse($resolver->tenantOfRecord(ScopedTicket::class, '0' . $ticket->getKey())); // @phpstan-ignore binaryOp.invalid
        self::assertFalse($resolver->tenantOfRecord(ScopedPost::class, '-0'));
        self::assertFalse($resolver->tenantOfRecord(ScopedPost::class, '01'));
        self::assertNull($resolver->tenantOfRecord(ScopedPost::class, '0'));
        self::assertNull($resolver->tenantOfRecord(ScopedPost::class, '-1'));
        self::assertNull($resolver->tenantOfRecord(ScopedPost::class, (string) \PHP_INT_MIN));
        self::assertFalse($resolver->tenantOfRecord(ScopedPost::class, '9223372036854775808'));
        self::assertFalse($resolver->tenantOfRecord(IntegerTypedPost::class, '07'));
        self::assertFalse($resolver->tenantOfRecord(ScopedTicket::class, \str_repeat('9', 19)));
        self::assertFalse($resolver->tenantOfRecord(ScopedTicket::class, \str_repeat('9', 11)));
        self::assertFalse($resolver->tenantOfRecord('posts', '1'));
        self::assertFalse($resolver->tenantOfRecord(StubGrantee::class, 'u1'));
        self::assertSame([['posts', '1'], [StubGrantee::class, 'u1']], $fallback->askedRecords);
    }

    /**
     * An integer key spelt other than as its canonical text names no record, as
     * the query scope compares keys, so `check()`, `checkMany()` and
     * `canEach()` deny it as `resource_unresolved` rather than decide record 7
     * past its own deny.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testANonCanonicalIntegerKeyNamesNoRecord(): void
    {
        $user = StubGrantee::create(['id' => 'u1']);

        $user->givePermission(Permission::create(['name' => 'posts:view']));
        TenantScopedPost::query()->create(['id' => 7]);
        TenantScopedPost::query()->create(['id' => 8]);

        foreach ([TenantScopedPost::class, ScopedPost::class] as $class) {
            self::attachToResource([$class, '7'], [['effect' => 'deny', 'actions' => ['posts:view']]]);
        }

        $manager = $this->resolveRequest($user);
        $pairs   = [
            'seven'      => [TenantScopedPost::class, '7'],
            'padded'     => [TenantScopedPost::class, '07'],
            'tenantless' => [ScopedPost::class, '07'],
            'signed'     => [ScopedPost::class, '-0'],
        ];
        $checks = \array_map(static fn (array $pair): CheckInput => new CheckInput('posts:view', $pair), $pairs);
        $reason = static fn (array $pair): ?DecisionReason => $manager->check('posts:view', $pair)->reason;
        $denied = ['seven' => DecisionReason::EXPLICIT_DENY, ...\array_fill_keys(['padded', 'tenantless', 'signed'], DecisionReason::RESOURCE_UNRESOLVED)];

        self::assertSame($denied, \array_map($reason, $pairs));
        self::assertSame($denied, \array_map(static fn (Decision $decision): ?DecisionReason => $decision->reason, $manager->checkMany($checks)));
        $allowed = $manager->canEach('posts:view', [...$pairs, 'eight' => [TenantScopedPost::class, '8']]);

        self::assertSame(['seven' => false, 'padded' => false, 'tenantless' => false, 'signed' => false, 'eight' => true], $allowed);
        self::assertSame([8], TenantScopedPost::query()->whereAuthorized('posts:view', [], $manager)->pluck('id')->all()); // @phpstan-ignore method.notFound
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
     * On PostgreSQL a key is looked up only when its column can hold it, as the
     * column's described type decides, here on a SQLite connection that reports
     * itself as PostgreSQL, which keeps any bytes.
     *
     * @return void
     */
    public function testOnPostgresOnlyAKeyTheColumnCanHoldIsLookedUp(): void
    {
        $default = config('database.default');

        config(['database.connections.reported_pgsql' => ['driver' => 'sqlite', 'database' => ':memory:'], 'database.default' => 'reported_pgsql']);

        DB::extend('reported_pgsql', static fn (array $config): SQLiteConnection => new class (new \PDO('sqlite::memory:'), ':memory:', '', $config) extends SQLiteConnection {
            /**
             * Report the connection as PostgreSQL.
             *
             * @return string
             */
            #[\Override]
            public function getDriverName(): string
            {
                return 'pgsql';
            }
        });

        try {
            DB::connection()->getSchemaBuilder()->create('scoped_uuid_documents', static function (Blueprint $table): void {
                $table->string('id')->primary();
                $table->string('tenant_type')->nullable();
                $table->string('tenant_id')->nullable();
            });

            UuidScopedDocument::query()->create(['id' => 'doc-a', 'tenant_type' => 'teams', 'tenant_id' => 't1']);
            UuidScopedDocument::query()->create(['id' => "\xff\xfe", 'tenant_type' => 'teams', 'tenant_id' => 't2']);

            $resolver = new DeclaredResourceTenant(new FixedResourceTenantResolver(null, false));

            self::assertEquals(new Reference('teams', 't1'), $resolver->tenantOfRecord(UuidScopedDocument::class, 'doc-a'));
            self::assertFalse($resolver->tenantOfRecord(UuidScopedDocument::class, "\xff\xfe"));
        } finally {
            config(['database.default' => $default]);
        }
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
     * Many models are answered at once, each as it would be on its own: a
     * declared model from its declaration, one whose tenant cannot be read left
     * out, and every other through the configured resolver, in bulk when it
     * answers in bulk, else left out, so each is asked on its own.
     *
     * @return void
     */
    public function testManyModelsAreAnsweredAsEachWouldBe(): void
    {
        $fallback = new FixedResourceTenantResolver(new Reference('fixed', '1'));
        $resolver = new DeclaredResourceTenant($fallback);
        $post     = TenantScopedPost::query()->create(['tenant_type' => 'teams', 'tenant_id' => '5']);
        $partial  = new TenantScopedPost(['id' => 3]);
        $long     = new TenantScopedPost(['id' => 4, 'tenant_type' => 'teams', 'tenant_id' => \str_repeat('9', 192)]);
        $other    = StubGrantee::create(['id' => 'u1']);

        $models = ['a' => $post, 'b' => new ScopedPost, 'c' => $partial, 'e' => $long, 'd' => $other];

        self::assertEquals(['a' => new Reference('teams', '5'), 'b' => null], $resolver->tenantsOf($models));
        self::assertSame([], $fallback->asked);
        self::assertSame([], $resolver->tenantsOf([]));

        $bulk = new CountingBulkTenants(['u1' => new Reference('bulk', '2')]);

        self::assertEquals(['a' => new Reference('teams', '5'), 'd' => new Reference('bulk', '2')], (new DeclaredResourceTenant($bulk))->tenantsOf(['a' => $post, 'd' => $other]));
        self::assertSame([['u1']], $bulk->bulkCalls);
    }

    /**
     * Many records of a declared type are looked up in one query on the write
     * connection, each answered as on its own: its tenant, false for a key that
     * names no record, one the column cannot hold or an integer key no record
     * has, every key that names a record none for a tenantless type; a key that
     * names no record is never looked up, and a string key not found under
     * exactly its spelling is left out, to be looked up on its own.
     *
     * @return void
     */
    public function testManyRecordsAreLookedUpInOneQuery(): void
    {
        $resolver = new DeclaredResourceTenant(new FixedResourceTenantResolver(null, false));
        $create   = static fn (string $tenant): RecordedTenantPost => RecordedTenantPost::query()->create(['tenant_type' => 'teams', 'tenant_id' => $tenant]);
        $posts    = \array_map($create, ['5', '6']);
        $first    = (string) $posts[0]->getKey(); // @phpstan-ignore cast.string
        $second   = (string) $posts[1]->getKey(); // @phpstan-ignore cast.string
        $ids      = ['a' => $first, 'b' => $second, 'c' => '0' . $first, 'd' => '999', 'e' => 'abc', 'f' => \str_repeat('9', 19)];

        QueryRecorder::reset();

        $tenants = $resolver->tenantsOfRecords(RecordedTenantPost::class, $ids);
        $lookups = \array_values(\array_filter(QueryRecorder::recorded(), static fn (QueryBuilder $query): bool => $query->wheres !== []));

        self::assertCount(1, $lookups);
        self::assertTrue($lookups[0]->useWritePdo);
        $isTenant = static fn (mixed $tenant): bool => $tenant instanceof Reference;

        self::assertEquals(['a' => new Reference('teams', '5'), 'b' => new Reference('teams', '6')], \array_filter($tenants, $isTenant));
        self::assertSame(['c' => false, 'd' => false, 'e' => false, 'f' => false], \array_filter($tenants, static fn (mixed $tenant): bool => !$isTenant($tenant)));
        self::assertSame(\array_keys($ids), \array_keys($tenants));

        foreach ($ids as $key => $id) {
            self::assertEquals($resolver->tenantOfRecord(RecordedTenantPost::class, $id), $tenants[$key]);
        }

        self::assertSame(['x' => null, 'y' => null, 'z' => false], $resolver->tenantsOfRecords(ScopedPost::class, ['x' => '1', 'y' => '2', 'z' => '02']));

        QueryRecorder::reset();

        self::assertSame(['c' => false, 'e' => false], $resolver->tenantsOfRecords(RecordedTenantPost::class, ['c' => '0' . $first, 'e' => 'abc']));
        self::assertSame([], QueryRecorder::recorded());

        TenantScopedDocument::query()->create(['code' => 'doc-a', 'tenant_type' => 'teams', 'tenant_id' => 't1']);

        self::assertEquals(['a' => new Reference('teams', 't1')], $resolver->tenantsOfRecords(TenantScopedDocument::class, ['a' => 'doc-a', 'b' => 'DOC-A', 'c' => 'missing']));
    }

    /**
     * A record whose tenant cannot be read, a key too long for a reference or
     * one holding neither text nor an integer, is left out of the bulk answer,
     * so its own lookup throws, failing its check alone.
     *
     * @return void
     */
    public function testARecordWhoseTenantCannotBeReadIsLeftOut(): void
    {
        $resolver = new DeclaredResourceTenant(new FixedResourceTenantResolver(null, false));
        $long     = RecordedTenantPost::query()->create(['tenant_type' => 'teams', 'tenant_id' => \str_repeat('9', 192)]);
        $odd      = UnreadableTenantPost::query()->create(['tenant_type' => 'teams', 'tenant_id' => UnreadableTenantPost::UNREADABLE]);
        $fine     = UnreadableTenantPost::query()->create(['tenant_type' => 'teams', 'tenant_id' => '5']);
        $key      = static fn (Model $post): string => (string) $post->getKey(); // @phpstan-ignore cast.string

        self::assertSame([], $resolver->tenantsOfRecords(RecordedTenantPost::class, ['long' => $key($long)]));
        self::assertEquals(['fine' => new Reference('teams', '5')], $resolver->tenantsOfRecords(UnreadableTenantPost::class, ['odd' => $key($odd), 'fine' => $key($fine)]));

        $unreadable = [[RecordedTenantPost::class, $long, \InvalidArgumentException::class], [UnreadableTenantPost::class, $odd, \UnexpectedValueException::class]];

        foreach ($unreadable as [$class, $post, $exception]) {
            try {
                $resolver->tenantOfRecord($class, $key($post));

                self::fail('The record\'s tenant cannot be read.');
            } catch (\Throwable $thrown) {
                self::assertInstanceOf($exception, $thrown);
            }
        }
    }

    /**
     * Records of a type no model declares are answered by the configured
     * resolver in bulk when it answers in bulk, and otherwise left out, so each
     * is asked on its own.
     *
     * @return void
     */
    public function testOtherRecordsAreLeftToTheConfiguredResolver(): void
    {
        $fallback = new FixedResourceTenantResolver(null, false);

        self::assertSame([], (new DeclaredResourceTenant($fallback))->tenantsOfRecords('posts', ['1']));
        self::assertSame([], $fallback->askedRecords);

        $bulk = new CountingBulkTenants(['1' => new Reference('teams', '5')]);

        self::assertEquals([new Reference('teams', '5'), false], (new DeclaredResourceTenant($bulk))->tenantsOfRecords('posts', ['1', '2']));
        self::assertSame([['1', '2']], $bulk->bulkCalls);
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
