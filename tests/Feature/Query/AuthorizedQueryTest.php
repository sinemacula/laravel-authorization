<?php

declare(strict_types = 1);

namespace Tests\Feature\Query;

use Illuminate\Contracts\Database\Query\Builder;
use Illuminate\Database\Connection;
use Illuminate\Database\Eloquent\Builder as EloquentBuilder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\Relation;
use Illuminate\Database\Query\Builder as QueryBuilder;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\After;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Exceptions\QueryScopeRefusedException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Query\AuthorizedQuery;
use SineMacula\Laravel\Authorization\Query\Enums\RefusalReason;
use SineMacula\Laravel\Authorization\Query\Reentrancy;
use SineMacula\Laravel\Authorization\Query\Refusal;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\ScopesQueries;
use Tests\Concerns\UsesAnAuthorizationConnection;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubTenant;
use Tests\Fixtures\QueryScoping\ClosureTenantTree;
use Tests\Fixtures\QueryScoping\ReplicatedGuardedPost;
use Tests\Fixtures\QueryScoping\ReplicatedPost;
use Tests\Fixtures\QueryScoping\ScopedPost;
use Tests\Fixtures\QueryScoping\SubtreeQueryTree;
use Tests\TestCase;

/**
 * Feature tests for the scope `whereAuthorized()` puts on a query: its place
 * held on the builder, the constraints grouped and the condition added when it
 * is applied, compiled when it is made and each time the query is compiled, and
 * guarded before and as it is compiled.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(AuthorizedQuery::class)]
final class AuthorizedQueryTest extends TestCase
{
    use ScopesQueries, UsesAnAuthorizationConnection;

    /**
     * The scope is compiled once when it is made, so a refusal throws then, not
     * when it is applied, and again each time the query is compiled, from the
     * state at that instant; two scopes have different identifiers.
     *
     * @return void
     */
    public function testTheScopeIsCompiledWhenMadeAndWhenTheQueryIsCompiled(): void
    {
        /** @var \ArrayObject<int, true> $compiled */
        $compiled = new \ArrayObject;
        $scope    = AuthorizedQuery::compiled(new ScopedPost, 'posts:view', static function () use ($compiled): string {
            $compiled[] = true;
            $count      = \count($compiled);

            return "{$count} = {$count}";
        });

        self::assertCount(1, $compiled);
        self::assertStringStartsWith('authorization.authorized:', $scope->identifier);
        self::assertNotSame($scope->identifier, self::scope()->identifier);

        $builder = ScopedPost::query();

        $scope->apply($builder, new ScopedPost);

        self::assertCount(1, $compiled);

        $query = $builder->getQuery();

        self::assertStringEndsWith('where (2 = 2)', $query->toSql());
        self::assertStringEndsWith('where (3 = 3)', $query->toSql());
        self::assertSame([], $builder->getBindings());

        $refused = self::refusalOf(static fn (): AuthorizedQuery => AuthorizedQuery::compiled(new ScopedPost, 'posts:view', static function (): string {
            throw QueryScopeRefusedException::of('posts:view', 'posts', new Refusal(RefusalReason::TOO_MANY_SCOPES));
        }));

        self::assertSame([RefusalReason::TOO_MANY_SCOPES], $refused->reasons());
    }

    /**
     * Applying the scope takes its place out, puts every other constraint in
     * one nested group with the bindings, in order, and adds the condition
     * after it; another scope's place stays at the top, and a query whose one
     * constraint is already a group joined with `and` is not grouped again.
     *
     * @return void
     */
    public function testApplyingGroupsTheOtherConstraintsAheadOfTheCondition(): void
    {
        $scope = self::scope();
        $other = self::scope();
        $query = ScopedPost::query()->where('title', 'a')->orWhere('title', 'b');

        $scope->holdPlaceOn($query->getQuery());
        $other->holdPlaceOn($query->getQuery());
        $query->where('status', 'live');
        $scope->apply($query, new ScopedPost);

        $wheres = $query->getQuery()->wheres;

        self::assertSame(['Nested', AuthorizedQuery::WHERE_TYPE, AuthorizedQuery::WHERE_TYPE], \array_column($wheres, 'type'));
        self::assertSame(['and', 'and', 'and'], \array_column($wheres, 'boolean'));
        self::assertSame([$other, $scope], \array_column($wheres, 'scope'));
        self::assertSame([false, true], \array_column($wheres, 'applied'));
        $grouped = \array_map(static fn (array $where): array => [$where['column'], $where['boolean']], $wheres[0]['query']->wheres);

        self::assertSame([['title', 'and'], ['title', 'or'], ['status', 'and']], $grouped);
        self::assertSame(['a', 'b', 'live'], $query->getBindings());
        self::assertSame(['a', 'b', 'live'], $wheres[0]['query']->getBindings());

        $grouped = ScopedPost::query()->where(static fn ($nested) => $nested->where('title', 'a')->orWhere('title', 'b'));
        $group   = $grouped->getQuery()->wheres[0]['query'];

        $scope->apply($grouped, new ScopedPost);

        self::assertSame($group, $grouped->getQuery()->wheres[0]['query']);

        $bare = ScopedPost::query();

        $scope->holdPlaceOn($bare->getQuery());
        $scope->apply($bare, new ScopedPost);

        self::assertSame([[AuthorizedQuery::WHERE_TYPE, true]], \array_map(static fn (array $where): array => [$where['type'], $where['applied']], $bare->getQuery()->wheres));
    }

    /**
     * The place, compiled because the scope was never applied, refuses, and
     * says how to call the macro; so does a condition naming no scope.
     *
     * @return void
     */
    public function testThePlaceRefusesWhenItIsCompiled(): void
    {
        $query = ScopedPost::query()->getQuery();

        self::scope()->holdPlaceOn($query);

        $refusal = self::refusalOf(static fn (): string => $query->toSql());

        self::assertSame([RefusalReason::SCOPE_REMOVED], $refusal->reasons());
        self::assertSame('call whereAuthorized() on the query that runs, after removing its global scopes', $refusal->refusals[0]->detail);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('A whereAuthorized() condition names no scope.');

        AuthorizedQuery::compileWhere($query, ['type' => AuthorizedQuery::WHERE_TYPE, 'applied' => true]);
    }

    /**
     * The guard groups the constraints added since the scope was applied, and
     * refuses a query whose condition was taken out, one joined with `or` after
     * it, one with a union, and one selecting from anything but the model's
     * table.
     *
     * @return void
     */
    public function testTheGuardGroupsLaterConstraintsAndRefusesAnEscape(): void
    {
        $scope  = self::scope();
        $guard  = static fn (QueryBuilder $query): array => self::refusalOf(static fn () => $scope->guard($query))->reasons();
        $scoped = static function () use ($scope): QueryBuilder {
            $query = ScopedPost::query()->where('title', 'a');

            $scope->apply($query, new ScopedPost);

            return $query->getQuery();
        };

        $later = $scoped()->whereRaw('status = \'live\' OR status = \'draft\'');

        $scope->guard($later);

        self::assertSame(['Nested', AuthorizedQuery::WHERE_TYPE], \array_column($later->wheres, 'type'));
        self::assertCount(2, $later->wheres[0]['query']->wheres);

        $emptied = $scoped();

        $emptied->wheres = [];

        self::assertSame([RefusalReason::SCOPE_REMOVED], $guard(ScopedPost::query()->where('title', 'a')->getQuery()));
        self::assertSame([RefusalReason::SCOPE_REMOVED], $guard($emptied));
        self::assertSame([RefusalReason::QUERY_OR], $guard($scoped()->orWhere('title', 'b')));
        self::assertSame([RefusalReason::QUERY_UNION], $guard($scoped()->union(ScopedPost::query()->toBase())));
        self::assertSame([RefusalReason::QUERY_FROM], $guard($scoped()->from('scoped_posts as p')));
    }

    /**
     * The grammar, compiling the condition after the guard, refuses a query
     * changed since: a constraint added at the top that is not a group, and one
     * joined with `or`; a group joined with `and` is let through, and an `or`
     * on the first constraint, whose boolean the grammar drops.
     *
     * @return void
     */
    public function testTheGrammarRefusesAQueryChangedAfterItsGuard(): void
    {
        $scope  = self::scope();
        $scoped = static function () use ($scope): QueryBuilder {
            $query = ScopedPost::query()->where('title', 'a');

            $scope->apply($query, new ScopedPost);

            $base = $query->getQuery();

            $base->applyBeforeQueryCallbacks();

            return $base;
        };

        $compiled = static fn (QueryBuilder $query): array => self::refusalOf(static fn (): string => $query->toSql())->reasons();

        self::assertSame([RefusalReason::QUERY_CHANGED], $compiled($scoped()->where('status', 'live')));
        self::assertSame([RefusalReason::QUERY_OR], $compiled($scoped()->orWhere(static fn (QueryBuilder $nested) => $nested->where('status', 'live'))));
        self::assertStringContainsString('(1 = 1) and (', $scoped()->where(static fn (QueryBuilder $nested) => $nested->where('status', 'live'))->toSql());

        $first = ScopedPost::query();

        $scope->apply($first, new ScopedPost);

        $base = $first->getQuery();

        $base->applyBeforeQueryCallbacks();

        $base->wheres[0]['boolean'] = 'or';

        self::assertStringEndsWith('where (1 = 1)', $base->toSql());
    }

    /**
     * Before it is scoped, a query with a union, or selecting from anything but
     * the model's table, is refused; any other is not. A refusal names the
     * model's morph type.
     *
     * @return void
     */
    public function testAQueryTheConditionCannotHoldForIsRefusedBeforeItIsScoped(): void
    {
        $scope = self::scope();

        $union = ScopedPost::query()->union(ScopedPost::query()->toBase())->getQuery();
        $sub   = ScopedPost::query()->fromSub(ScopedPost::query()->toBase(), 'scoped_posts')->getQuery();

        self::assertSame([RefusalReason::QUERY_UNION], self::refusalOf(static fn () => $scope->assertScopable($union))->reasons());
        self::assertSame([RefusalReason::QUERY_FROM], self::refusalOf(static fn () => $scope->assertScopable($sub))->reasons());

        $scope->assertScopable(ScopedPost::query()->where('title', 'a')->orWhere('title', 'b')->getQuery());

        self::assertSame((new ScopedPost)->getMorphClass(), self::refusalOf(static fn () => $scope->assertScopable(ScopedPost::query()->from('other')->getQuery()))->resourceType);

        Relation::morphMap(['post' => ScopedPost::class]);

        self::assertSame('post', self::refusalOf(static fn () => self::scope()->guard(ScopedPost::query()->getQuery()))->resourceType);
    }

    /**
     * Every compile is marked as deciding a query scope, the one when the scope
     * is made and each the grammar asks for, and the mark is gone after.
     *
     * @return void
     */
    public function testEveryCompileIsMarkedAsDeciding(): void
    {
        /** @var \ArrayObject<int, bool> $marks */
        $marks   = new \ArrayObject;
        $compile = static function () use ($marks): string {
            $marks[] = Reentrancy::isDeciding();

            return '1 = 1';
        };

        $scope   = AuthorizedQuery::compiled(new ScopedPost, 'posts:view', $compile);
        $builder = ScopedPost::query()->withGlobalScope($scope->identifier, $scope);

        $scope->holdPlaceOn($builder->getQuery());
        $builder->toSql();

        self::assertSame([true, true], $marks->getArrayCopy());
        self::assertFalse(Reentrancy::isDeciding());
    }

    /**
     * A query run itself whose condition reads the attachments runs on the
     * write connection, as `check()` reads them, however it runs: rows, a
     * count, an existence, a page, a cursor, chunks and a lazy collection, and
     * with the model-level scope too. The read connection holds no posts yet,
     * so a query run there would find none.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARunQueryReadingTheAttachmentsRunsOnTheWriteConnection(): void
    {
        $manager = $this->replicated();
        $scoped  = static fn (): EloquentBuilder => ReplicatedPost::query()->whereAuthorized('posts:view', [], $manager)->orderBy('id'); // @phpstan-ignore method.notFound
        $ids     = static fn (iterable $posts): array => \array_values(\array_map(static fn (Model $post): mixed => $post->getKey(), [...$posts]));

        $chunked = [];

        $scoped()->chunkById(1, static function (iterable $posts) use (&$chunked, $ids): void {
            \array_push($chunked, ...$ids($posts));
        });

        self::assertSame([1, 3], $scoped()->pluck('id')->all());
        self::assertSame(2, $scoped()->count());
        self::assertTrue($scoped()->where('id', 3)->exists());
        self::assertSame([1, 3], $ids($scoped()->paginate(5)->items()));
        self::assertSame([1, 3], $ids($scoped()->cursor()));
        self::assertSame([1, 3], $chunked);
        self::assertSame([1, 3], $ids($scoped()->lazy(1)));
        self::assertSame([1, 3], ReplicatedGuardedPost::query()->orderBy('id')->pluck('id')->all());
        self::assertSame(2, ReplicatedGuardedPost::query()->count());
    }

    /**
     * A query whose condition reads no authorization table is left on the read
     * connection, which holds no posts yet.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAQueryReadingNoAuthorizationTableStaysOnTheReadConnection(): void
    {
        $manager = $this->replicated();

        $notes = static fn (): EloquentBuilder => ReplicatedPost::query()->whereAuthorized('notes:view', [], $manager)->orderBy('id'); // @phpstan-ignore method.notFound

        self::assertSame([], $notes()->pluck('id')->all());
        self::assertSame([1, 2, 3], $notes()->useWritePdo()->pluck('id')->all());
    }

    /**
     * A query whose condition reads the attachments but is not itself run (one
     * nested whole in another, by either scope, one compiled to text, and a
     * grouped page's count, which Laravel runs as another query around it)
     * cannot be put on the write connection, so it is refused; inside a
     * transaction, where Laravel reads on the write connection, it is not.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAQueryReadingTheAttachmentsThatIsNotRunIsRefused(): void
    {
        $manager = $this->replicated();
        $outer   = static fn (): QueryBuilder => DB::connection(ReplicatedPost::CONNECTION)->table('scoped_posts');
        $scoped  = static fn (): EloquentBuilder => ReplicatedPost::query()->whereAuthorized('posts:view', [], $manager); // @phpstan-ignore method.notFound

        $shapes = [
            'nested'             => static fn (): mixed => $outer()->whereExists($scoped())->count(),
            'nested model scope' => static fn (): mixed => $outer()->whereExists(ReplicatedGuardedPost::query())->count(),
            'text'               => static fn (): mixed => $scoped()->toSql(),
            'grouped page'       => static fn (): mixed => $scoped()->groupBy('id')->paginate(),
        ];

        foreach ($shapes as $shape => $run) {
            try {
                $run();

                self::fail("The {$shape} query was not refused.");
            } catch (QueryScopeRefusedException $exception) {
                self::assertSame([RefusalReason::READ_REPLICA], $exception->reasons(), $shape);
            }
        }

        /** @var \Illuminate\Database\Connection $connection */
        $connection = DB::connection(ReplicatedPost::CONNECTION);

        self::assertSame(3, $connection->transaction(static fn (): int => $outer()->whereExists($scoped())->count()));
    }

    /**
     * A query run itself whose condition nests a subtree runs on the write
     * connection; one nesting it in another is refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAQueryNestingASubtreeRunsOnTheWriteConnection(): void
    {
        $manager = $this->replicated(true);
        $scoped  = static fn (): EloquentBuilder => ReplicatedPost::query()->whereAuthorized('posts:edit', [], $manager)->orderBy('id'); // @phpstan-ignore method.notFound

        self::assertSame([1, 3, 4, 5], $scoped()->pluck('id')->all());

        $nested = static fn (): int => DB::connection(ReplicatedPost::CONNECTION)->table('scoped_posts')->whereExists($scoped())->count();

        self::assertSame([RefusalReason::READ_REPLICA], self::refusalOf($nested)->reasons());
    }

    /**
     * Forget the morph map a test set. /** Forget the morph map a test set.
     *
     * @return void
     */
    #[After]
    protected function forgetMorphMap(): void
    {
        Relation::morphMap([], false);
    }

    /**
     * Keep posts on the `authorization` connection, beside the authorization
     * tables, give it a read connection holding no posts, and return the
     * manager of a subject who may view every post but the second, denied by a
     * policy attached to it under either model; and, when asked, who may edit
     * the posts of an organisation's subtree, read through a tree nested from
     * that connection.
     *
     * @param  bool  $isTree
     * @return \SineMacula\Laravel\Authorization\AuthorizationManager
     *
     * @throws \Throwable
     */
    private function replicated(bool $isTree = false): AuthorizationManager
    {
        $this->useAnAuthorizationConnection();

        /** @var \Illuminate\Database\Connection $connection */
        $connection = DB::connection(ReplicatedPost::CONNECTION);

        self::createReplicatedTables($connection);

        $user = StubIdentity::create(['id' => 'u1']);

        foreach ([1, 2, 3] as $id) {
            ReplicatedPost::query()->create(['id' => $id]);
        }

        $user->givePermission(Permission::create(['name' => 'posts:view']));
        $user->givePermission(Permission::create(['name' => 'notes:view']));
        self::attachToResource([ReplicatedPost::class, '2'], [['effect' => 'deny', 'actions' => ['posts:*']]]);
        self::attachToResource([ReplicatedGuardedPost::class, '2'], [['effect' => 'deny', 'actions' => ['posts:*']]]);

        if ($isTree) {
            $this->seedTree($connection, $user);
        }

        $manager = $this->resolveRequest($user, $isTree ? StubTenant::query()->find('o1') : null);

        // A replica that has every table but lags behind every write.
        $replica = new \PDO('sqlite::memory:');

        foreach ($connection->select('select sql from sqlite_master where type = \'table\' and sql is not null and name not like \'sqlite_%\'') as $table) {
            $replica->exec((string) ((array) $table)['sql']); // @phpstan-ignore cast.string
        }

        $connection->setReadPdo($replica);

        return $manager;
    }

    /**
     * Grow a tree of an organisation, its account and a sibling organisation,
     * with a post in each, read through a subtree nested from the connection,
     * and let the subject edit the posts of the organisation's subtree.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  \Tests\Feature\Stubs\StubIdentity  $user
     * @return void
     */
    private function seedTree(Connection $connection, StubIdentity $user): void
    {
        $type = (new StubTenant)->getMorphClass();

        $this->app?->instance(TenantTree::class, new SubtreeQueryTree(static fn (Reference $tenant): Builder => DB::connection(ReplicatedPost::CONNECTION)
            ->table(ClosureTenantTree::TABLE)
            ->select(['descendant_type as tenant_type', 'descendant_id as tenant_id'])
            ->where('ancestor_type', $tenant->type)
            ->where('ancestor_id', $tenant->id)));

        foreach (['o1' => null, 'a1' => 'o1', 'o2' => null] as $id => $parent) {
            StubTenant::query()->create(['id' => $id]);
            ClosureTenantTree::add(new Reference($type, $id), $parent === null ? null : new Reference($type, $parent));
            ReplicatedPost::query()->create(['tenant_type' => $type, 'tenant_id' => $id]);
        }

        $connection->table(ClosureTenantTree::TABLE)->insert(DB::table(ClosureTenantTree::TABLE)->get()->map(static fn (object $row): array => (array) $row)->all());
        $user->givePermission(Permission::create(['name' => 'posts:edit']), null, new Reference($type, 'o1'));
    }

    /**
     * Create the posts and the closure table of the tree on the connection.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @return void
     */
    private static function createReplicatedTables(Connection $connection): void
    {
        $schema = $connection->getSchemaBuilder();

        $schema->create('scoped_posts', static function (Blueprint $table): void {
            $table->increments('id');
            $table->string('tenant_type')->nullable();
            $table->string('tenant_id')->nullable();
        });

        $schema->create(ClosureTenantTree::TABLE, static function (Blueprint $table): void {
            foreach (['ancestor_type', 'ancestor_id', 'descendant_type', 'descendant_id'] as $column) {
                $table->string($column, 191);
            }

            $table->unsignedInteger('depth');
        });
    }

    /**
     * Return a scope keeping every row. /** Return a scope keeping every row.
     *
     * @return \SineMacula\Laravel\Authorization\Query\AuthorizedQuery
     */
    private static function scope(): AuthorizedQuery
    {
        return AuthorizedQuery::compiled(new ScopedPost, 'posts:view', static fn (): string => '1 = 1');
    }
}
