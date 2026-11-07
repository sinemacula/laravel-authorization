<?php

declare(strict_types = 1);

namespace Tests\Feature\Registrars;

use Illuminate\Container\Container;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\Query\Builder as QueryBuilder;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Evaluation\Policy as EvaluationPolicy;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Query\Enums\RefusalReason;
use SineMacula\Laravel\Authorization\Registrars\QueryScopeRegistrar;
use Tests\Concerns\ScopesQueries;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubTenant;
use Tests\Fixtures\QueryScoping\PostOwner;
use Tests\Fixtures\QueryScoping\ScopedDocument;
use Tests\Fixtures\QueryScoping\ScopedPost;
use Tests\Fixtures\QueryScoping\SealedModels;
use Tests\Fixtures\QueryScoping\TenantScopedPost;
use Tests\TestCase;

/**
 * Feature tests for the `whereAuthorized()` builder macro, end to end: the rows
 * it keeps, how it joins the application's constraints, the queries it refuses
 * and the executions it is compiled again for.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(QueryScopeRegistrar::class)]
final class QueryScopeRegistrarTest extends TestCase
{
    use ScopesQueries;

    /**
     * The macro is registered on every Eloquent builder, and keeps the rows the
     * current subject may take the action on: every one when it holds the
     * action, none when it does not, and none for a guest.
     *
     * @return void
     */
    public function testTheMacroKeepsTheRowsTheCurrentSubjectMayActOn(): void
    {
        $user  = StubIdentity::create(['id' => 'u1']);
        $other = StubIdentity::create(['id' => 'u2']);

        $user->givePermission(Permission::create(['name' => 'posts:view']));

        self::createPosts(3);

        self::assertTrue(Builder::hasGlobalMacro(QueryScopeRegistrar::MACRO));
        self::assertCount(3, $this->scoped($this->resolveRequest($user)));
        self::assertCount(0, $this->scoped($this->resolveRequest($other)));
        self::assertCount(3, self::authorized(ScopedPost::query(), 'posts:view', Authorization::for($user))->get());
        self::assertCount(0, self::authorized(ScopedPost::query(), 'posts:view', Authorization::forUser(null))->get());
    }

    /**
     * The subject is the one `check()` decides about: a policy override and a
     * cap of the manager given count, and so does the caller's context, held
     * under `input`.
     *
     * @return void
     */
    public function testTheManagersOverrideCapsAndContextCount(): void
    {
        $user    = StubIdentity::create(['id' => 'u1']);
        $manager = $this->resolveRequest($user);
        $flagged = ['effect' => 'allow', 'actions' => ['posts:view'], 'conditions' => ['eq' => ['input.flag' => 'on']]];
        $allow   = EvaluationPolicy::fromArray(['name' => 'override', 'statements' => [$flagged]]);

        self::createPosts(2);

        $overridden = $manager->withPolicies([$allow]);

        self::assertCount(2, self::authorized(ScopedPost::query(), 'posts:view', $overridden, ['flag' => 'on'])->get());
        self::assertCount(0, self::authorized(ScopedPost::query(), 'posts:view', $overridden, ['flag' => 'off'])->get());
        self::assertCount(0, self::authorized(ScopedPost::query(), 'posts:view', $overridden->capped(['other:*']), ['flag' => 'on'])->get());
    }

    /**
     * A refusal leaves the builder as it was: its SQL, bindings, conditions,
     * scopes and before-query callbacks.
     *
     * @return void
     */
    public function testARefusalLeavesTheBuilderUnchanged(): void
    {
        $user = StubIdentity::create(['id' => 'u1']);

        $user->attachPolicy(self::storedPolicy('record', [['effect' => 'deny', 'actions' => ['posts:view'], 'resources' => [(new ScopedPost)->getMorphClass() . ':1']]]));

        self::createPosts(2);

        $builder = ScopedPost::query()->where('title', 'like', 'post%')->orWhere('title', 'b');

        $builder->getQuery()->beforeQuery(static function (): void {});

        $base   = $builder->getQuery();
        $state  = static fn (): array => [$builder->toSql(), $builder->getBindings(), $base->wheres, \count($base->beforeQueryCallbacks), $builder->removedScopes()];
        $before = $state();

        self::refusalOf(fn (): Builder => self::authorized($builder, 'posts:view', $this->resolveRequest($user)));

        self::assertSame($before, $state());
        self::assertCount(2, $builder->get());
    }

    /**
     * The condition, with no bindings, follows every one of the application's,
     * which the scope puts in one group, one added after the macro included.
     *
     * @return void
     */
    public function testTheConditionJoinsTheApplicationsConstraintsWithAnd(): void
    {
        $user = StubIdentity::create(['id' => 'u1']);

        $user->givePermission(Permission::create(['name' => 'posts:view']));

        foreach (['a', 'b', 'c', 'd'] as $title) {
            ScopedPost::query()->create(['title' => $title]);
        }

        $query = self::authorized(ScopedPost::query()->where('title', 'a')->orWhere('title', 'b'), 'posts:view', $this->resolveRequest($user))->orWhere('title', 'c');
        $wrap  = static fn (string $column): string => DB::connection()->getQueryGrammar()->wrap($column);

        self::assertSame(['a', 'b', 'c'], $query->getBindings());
        $title = $wrap('title');

        $key = $wrap('scoped_posts.id');

        self::assertSame("select * from {$wrap('scoped_posts')} where ({$title} = ? or {$title} = ? or {$title} = ?) and ({$key} IS NOT NULL)", $query->toSql());
        self::assertSame(['a', 'b', 'c'], $query->orderBy('title')->pluck('title')->all());
    }

    /**
     * A query that would escape the condition is refused when it runs: a union,
     * another table selected from and the scope removed, each after the macro,
     * and the base query run past the scope; the union and the other table are
     * refused by the macro too, and scopes removed before it are not.
     *
     * @return void
     */
    public function testAQueryThatWouldEscapeTheConditionIsRefused(): void
    {
        $user    = StubIdentity::create(['id' => 'u1']);
        $manager = $this->resolveRequest($user);
        $scoped  = static fn (): Builder => self::authorized(ScopedPost::query(), 'posts:view', $manager);

        $refused = static fn (\Closure $query): array => self::refusalOf($query)->reasons();

        self::assertSame([RefusalReason::QUERY_UNION], $refused(static fn (): Collection => $scoped()->union(ScopedPost::query()->toBase())->get()));
        self::assertSame([RefusalReason::QUERY_FROM], $refused(static fn (): Collection => $scoped()->from('scoped_posts as p')->get()));
        self::assertSame([RefusalReason::SCOPE_REMOVED], $refused(static fn (): Collection => $scoped()->withoutGlobalScopes()->get()));
        self::assertSame([RefusalReason::SCOPE_REMOVED], $refused(static fn (): mixed => $scoped()->getQuery()->get()));
        $union = static fn (): Builder => ScopedPost::query()->union(ScopedPost::query()->toBase());

        self::assertSame([RefusalReason::QUERY_UNION], $refused(static fn (): Builder => self::authorized($union(), 'posts:view', $manager)));
        self::assertSame([RefusalReason::QUERY_FROM], $refused(static fn (): Builder => self::authorized(ScopedPost::query()->from('scoped_posts as p'), 'posts:view', $manager)));
        self::assertCount(0, self::authorized(ScopedPost::query()->withoutGlobalScopes(), 'posts:view', $manager)->get());
    }

    /**
     * Pagination, chunks, counts and existence agree with `check()` over the
     * candidates, and the scope runs no query on the model's table of its own:
     * each runs exactly the queries it runs on the allowed rows alone.
     *
     * @return void
     */
    public function testPaginationAndCountsAgreeWithCheck(): void
    {
        [$t1, $t2] = [StubTenant::query()->create(['id' => 't1']), StubTenant::query()->create(['id' => 't2'])];
        $user      = StubIdentity::create(['id' => 'u1']);
        $manager   = $this->resolveRequest($user, $t1);

        $user->givePermission(Permission::create(['name' => 'posts:view']), null, $t1);

        foreach ([null, $t1, $t2, $t1, null, $t2, $t1] as $index => $tenant) {
            TenantScopedPost::query()->create(['title' => 'p' . $index, 'tenant_type' => $tenant?->getMorphClass(), 'tenant_id' => $tenant?->getKey()]);
        }

        $allowed = TenantScopedPost::query()->orderBy('id')->get()->filter(static fn (Model $post): bool => $manager->can('posts:view', $post))->pluck('title')->all();
        $scoped  = static fn (): Builder => self::authorized(TenantScopedPost::query(), 'posts:view', $manager)->orderBy('id');
        $plain   = static fn (): Builder => TenantScopedPost::query()->whereIn('title', $allowed)->orderBy('id');

        self::assertSame(['p0', 'p1', 'p3', 'p4', 'p6'], $allowed);

        $runs = [
            'paginate'       => static fn (\Closure $query): array => [$query()->paginate(2)->total(), \array_column($query()->paginate(2, ['*'], 'page', 2)->items(), 'title')],
            'simplePaginate' => static fn (\Closure $query): array => \array_column($query()->simplePaginate(2, ['*'], 'page', 3)->items(), 'title'),
            'cursorPaginate' => static fn (\Closure $query): array => \array_column($query()->cursorPaginate(3)->items(), 'title'),
            'chunkById'      => static function (\Closure $query): array {
                $titles = [];

                $query()->chunkById(2, static function (Collection $posts) use (&$titles): void {
                    $titles = [...$titles, ...$posts->pluck('title')->all()];
                });

                return $titles;
            },
            'count'  => static fn (\Closure $query): int => $query()->count(),
            'exists' => static fn (\Closure $query): bool => $query()->where('title', 'p2')->exists(),
        ];

        $expected = ['paginate' => [5, ['p3', 'p4']], 'simplePaginate' => ['p6'], 'cursorPaginate' => ['p0', 'p1', 'p3'], 'chunkById' => $allowed, 'count' => 5, 'exists' => false];

        foreach ($runs as $name => $run) {
            $run($scoped);

            $scopedQueries = self::queriesOnTheTable(static function () use ($expected, $name, $run, $scoped): void {
                self::assertSame($expected[$name], $run($scoped), $name);
            });
            $plainQueries = self::queriesOnTheTable(static fn (): mixed => $run($plain));

            self::assertSame($plainQueries, $scopedQueries, $name);
        }
    }

    /**
     * The scope is compiled again from the state at each execution, so a
     * permission revoked after the macro, and one granted, is seen when the
     * query runs; two calls keep only the rows both allow.
     *
     * @return void
     */
    public function testEachExecutionIsDecidedFromTheStateThen(): void
    {
        $user    = StubIdentity::create(['id' => 'u1']);
        $manager = $this->resolveRequest($user);
        $view    = Permission::create(['name' => 'posts:view']);

        $user->givePermission($view);

        self::createPosts(2);

        $query = self::authorized(ScopedPost::query(), 'posts:view', $manager);
        $both  = self::authorized(self::authorized(ScopedPost::query(), 'posts:view', $manager), 'posts:edit', $manager);

        self::assertCount(2, $query->get());
        self::assertCount(0, $both->get());

        $user->revokePermission($view);

        self::assertCount(0, $query->get());

        $user->givePermission($view);
        $user->givePermission(Permission::create(['name' => 'posts:edit']));

        self::assertCount(2, $query->get());
        self::assertCount(2, $both->get());
    }

    /**
     * An update or a deletion through the scope touches only the rows the
     * subject may act on.
     *
     * @return void
     */
    public function testUpdatesAndDeletionsAreScoped(): void
    {
        $user = StubIdentity::create(['id' => 'u1']);

        $user->givePermission(Permission::create(['name' => 'posts:edit']));

        foreach (['abc', '', 'def'] as $code) {
            ScopedDocument::query()->create(['code' => $code, 'title' => 'draft']);
        }

        $manager = $this->resolveRequest($user);

        self::assertSame(2, self::authorized(ScopedDocument::query(), 'posts:edit', $manager)->update(['title' => 'edited']));
        self::assertSame(['edited', 'draft', 'edited'], ScopedDocument::query()->orderBy('row_id')->pluck('title')->all());
        self::assertSame(0, self::authorized(ScopedDocument::query(), 'posts:delete', $manager)->delete());
        self::assertSame(3, ScopedDocument::query()->count());
    }

    /**
     * The leaks a broader scope would have are refused: `-0`, a literal `*`
     * key, a record's id, a `retrieved` listener and an overridden
     * `getAttribute()`.
     *
     * @return void
     */
    public function testTheLeaksOfABroaderScopeAreRefused(): void
    {
        $user    = StubIdentity::create(['id' => 'u1']);
        $manager = $this->resolveRequest($user);
        $type    = (new ScopedPost)->getMorphClass();

        foreach (['-0', '\*', '1'] as $index => $id) {
            $user->attachPolicy(self::storedPolicy('leak-' . $index, [['effect' => 'allow', 'actions' => ['posts:view'], 'resources' => [$type . ':' . $id]]]));
        }

        $overriding = SealedModels::overriding('getAttribute')->newQuery();

        $refusal = self::refusalOf(static fn (): Builder => self::authorized(ScopedPost::query(), 'posts:view', $manager));

        self::assertSame(\array_fill(0, 3, RefusalReason::RESOURCE_PATTERN), $refusal->reasons());
        self::assertSame([RefusalReason::MODEL_OVERRIDE], self::refusalOf(static fn (): Builder => self::authorized($overriding, 'posts:edit', $manager))->reasons());

        ScopedDocument::retrieved(static function (ScopedDocument $document): void {
            $document->setAttribute('tenant_id', 'other');
        });

        self::assertSame([RefusalReason::MODEL_LISTENER], self::refusalOf(static fn (): Builder => self::authorized(ScopedDocument::query(), 'posts:edit', $manager))->reasons());
    }

    /**
     * The macro called inside a `where` group, an `or` one or a negated one,
     * whose scope Laravel never applies, refuses when the query runs, never
     * keeping every row.
     *
     * @return void
     */
    public function testTheMacroInsideAWhereGroupRefuses(): void
    {
        $manager = $this->resolveRequest(StubIdentity::create(['id' => 'u1']));
        $scoped  = static fn (Builder $nested): Builder => self::authorized($nested, 'posts:view', $manager);

        self::createPosts(2);

        $groups = [
            'where'   => static fn (Builder $query): Builder => $query->where($scoped),
            'or'      => static fn (Builder $query): Builder => $query->where('title', 'x')->orWhere($scoped),
            'not'     => static fn (Builder $query): Builder => $query->whereNot($scoped),
            'or-more' => static fn (Builder $query): Builder => $query->where(static fn (Builder $nested): Builder => $scoped($nested)->orWhere('status', 'live')),
        ];

        foreach ($groups as $name => $group) {
            self::assertSame([RefusalReason::SCOPE_REMOVED], self::refusalOf(static fn (): Collection => $group(ScopedPost::query())->get())->reasons(), $name);
        }
    }

    /**
     * A relation scoped in its definition keeps the rows the subject may view
     * when it is loaded, lazily or eagerly; where Laravel takes only its
     * constraints, into an existence or count query, it refuses.
     *
     * @return void
     */
    public function testARelationScopedInItsDefinitionRefusesWhereItsScopeIsDropped(): void
    {
        $user  = StubIdentity::create(['id' => 'u1']);
        $owner = PostOwner::query()->create(['title' => 'post 0']);

        self::createPosts(1);
        $this->resolveRequest($user);

        self::assertCount(0, $owner->visiblePosts);

        $user->givePermission(Permission::create(['name' => 'posts:view']));
        $this->resolveRequest($user);

        self::assertCount(1, $owner->visiblePosts()->get());
        self::assertCount(1, PostOwner::query()->with('visiblePosts')->firstOrFail()->visiblePosts);

        $uses = [
            'whereHas'   => static fn (): mixed => PostOwner::query()->whereHas('visiblePosts')->get(),
            'has'        => static fn (): mixed => PostOwner::query()->has('visiblePosts', '>=', 2)->get(),
            'withCount'  => static fn (): mixed => PostOwner::query()->withCount('visiblePosts')->get(),
            'withExists' => static fn (): mixed => PostOwner::query()->withExists('visiblePosts')->get(),
        ];

        foreach ($uses as $name => $use) {
            self::assertSame([RefusalReason::SCOPE_REMOVED], self::refusalOf($use)->reasons(), $name);
        }
    }

    /**
     * A scoped builder another query takes whole, as `whereHas()` and
     * `whereExists()` do, is decided each time that query runs; one taken as
     * SQL text, as `whereIn()` does, is decided when it is taken in, and that
     * decision kept for as long as the other query is.
     *
     * @return void
     */
    public function testAScopedSubqueryIsDecidedWhenItsSqlIsWritten(): void
    {
        $user    = StubIdentity::create(['id' => 'u1']);
        $manager = $this->resolveRequest($user);
        $view    = Permission::create(['name' => 'posts:view']);

        PostOwner::query()->create(['title' => 'post 0']);
        self::createPosts(1);
        $user->givePermission($view);

        $whole  = PostOwner::query()->whereHas('posts', static fn (Builder $posts): Builder => self::authorized($posts, 'posts:view', $manager));
        $exists = PostOwner::query()->whereExists(self::authorized(ScopedPost::query(), 'posts:view', $manager)->whereColumn('scoped_posts.title', 'scoped_tickets.title'));
        $text   = ScopedPost::query()->whereIn('id', self::authorized(ScopedPost::query(), 'posts:view', $manager)->select('id'));

        self::assertSame([1, 1, 1], [$whole->count(), $exists->count(), $text->count()]);

        $user->revokePermission($view);

        self::assertSame([0, 0, 1], [$whole->count(), $exists->count(), $text->count()]);
        self::assertCount(0, self::authorized(ScopedPost::query(), 'posts:view', $manager)->get());
    }

    /**
     * A raw condition holding `or`, as a string or an expression, before the
     * macro or added by a global scope applied after it, is grouped, so it
     * cannot reach past the scope's condition.
     *
     * @return void
     */
    public function testARawConditionHoldingOrIsGrouped(): void
    {
        $manager = $this->resolveRequest(StubIdentity::create(['id' => 'u1']));

        foreach (['live', 'live', 'draft'] as $status) {
            ScopedPost::query()->create(['title' => 'post', 'status' => $status]);
        }

        $raw     = static fn (Builder $query): Builder => $query->whereRaw('1 = 1 OR status = \'live\'');
        $queries = [
            'raw'        => self::authorized(ScopedPost::query()->whereRaw('status = \'live\' OR status = \'x\''), 'posts:view', $manager),
            'expression' => self::authorized(ScopedPost::query()->where(DB::raw('status = \'live\' OR status = \'x\'')), 'posts:view', $manager),
            'scope'      => self::authorized(ScopedPost::query(), 'posts:view', $manager)->withGlobalScope('raw', $raw),
        ];

        foreach ($queries as $name => $query) {
            self::assertSame(0, $query->count(), $name);
            self::assertCount(0, $query->get(), $name);
        }
    }

    /**
     * A comment at the end of a raw condition cannot swallow the scope's
     * condition: the group it sits in is left unclosed, and the database
     * refuses the query.
     *
     * @return void
     */
    public function testACommentInARawConditionCannotSwallowTheCondition(): void
    {
        $manager = $this->resolveRequest(StubIdentity::create(['id' => 'u1']));

        ScopedPost::query()->create(['title' => 'post', 'status' => 'live']);

        $this->expectException(QueryException::class);

        self::authorized(ScopedPost::query()->whereRaw('status = \'live\' -- '), 'posts:view', $manager)->get();
    }

    /**
     * A before-query callback registered after the macro runs before its guard,
     * so one joining an `or`, taking the conditions out, adding a union or
     * selecting from another table is refused, and one adding a condition has
     * it grouped.
     *
     * @return void
     */
    public function testABeforeQueryCallbackAfterTheMacroCannotEscapeTheCondition(): void
    {
        $manager = $this->resolveRequest(StubIdentity::create(['id' => 'u1']));

        self::createPosts(2);

        $callbacks = [
            'or'    => [RefusalReason::QUERY_OR, static fn (QueryBuilder $query): QueryBuilder => $query->orWhere('title', 'post 0')],
            'clear' => [RefusalReason::SCOPE_REMOVED, static function (QueryBuilder $query): void {
                $query->wheres = [];
            }],
            'union' => [RefusalReason::QUERY_UNION, static fn (QueryBuilder $query): QueryBuilder => $query->union(ScopedPost::query()->toBase())],
            'from'  => [RefusalReason::QUERY_FROM, static fn (QueryBuilder $query): QueryBuilder => $query->from('scoped_posts as p')],
        ];

        foreach ($callbacks as $name => [$reason, $callback]) {
            $query = self::authorized(ScopedPost::query(), 'posts:view', $manager);

            $query->getQuery()->beforeQuery($callback);

            self::assertSame([$reason], self::refusalOf(static fn (): Collection => $query->get())->reasons(), $name);
        }

        $added = self::authorized(ScopedPost::query(), 'posts:view', $manager);

        $added->getQuery()->beforeQuery(static fn (QueryBuilder $query): QueryBuilder => $query->whereRaw('1 = 1 OR title = \'post 0\''));

        self::assertCount(0, $added->get());
    }

    /**
     * A base query taken with `toBase()` is decided afresh each time it runs,
     * and refused once it is widened with `or` or given a condition outside the
     * group.
     *
     * @return void
     */
    public function testABaseQueryIsDecidedEachTimeItRuns(): void
    {
        $user    = StubIdentity::create(['id' => 'u1']);
        $manager = $this->resolveRequest($user);
        $view    = Permission::create(['name' => 'posts:view']);

        self::createPosts(2);
        $user->givePermission($view);

        $base = self::authorized(ScopedPost::query(), 'posts:view', $manager)->toBase();

        self::assertCount(2, $base->get());

        $user->revokePermission($view);

        self::assertCount(0, $base->get());
        self::assertSame([RefusalReason::QUERY_OR], self::refusalOf(static fn (): mixed => (clone $base)->orWhere('title', 'post 0')->get())->reasons());
        self::assertSame([RefusalReason::QUERY_CHANGED], self::refusalOf(static fn (): mixed => (clone $base)->where('title', 'post 0')->get())->reasons());
    }

    /**
     * Without an authorization manager bound, and none given, the macro cannot
     * scope a query.
     *
     * @return void
     */
    public function testWithoutAManagerTheMacroCannotScope(): void
    {
        $container = Container::getInstance();

        Container::setInstance(new Container);

        try {
            $this->expectException(\LogicException::class);
            $this->expectExceptionMessage('whereAuthorized() needs the authorization manager, which is not bound.');

            QueryScopeRegistrar::scope(ScopedPost::query(), 'posts:view');
        } finally {
            Container::setInstance($container);
        }
    }

    /**
     * Create the number of posts given.
     *
     * @param  int  $count
     * @return void
     */
    private static function createPosts(int $count): void
    {
        for ($index = 0; $index < $count; $index++) {
            ScopedPost::query()->create(['title' => 'post ' . $index]);
        }
    }

    /**
     * Return the posts the manager's subject may view.
     *
     * @param  \SineMacula\Laravel\Authorization\AuthorizationManager  $manager
     * @return \Illuminate\Database\Eloquent\Collection<int, \Illuminate\Database\Eloquent\Model>
     */
    private function scoped(AuthorizationManager $manager): Collection
    {
        self::assertSame($manager, $this->app?->make(AuthorizationManager::class));

        return self::authorized(ScopedPost::query(), 'posts:view')->get();
    }

    /**
     * Return the queries the callback runs on the posts' table, as their SQL up
     * to the table.
     *
     * @param  \Closure(): mixed  $callback
     * @return list<string>
     */
    private static function queriesOnTheTable(\Closure $callback): array
    {
        $queries = [];

        DB::listen(static function (object $query) use (&$queries): void {
            /** @var \Illuminate\Database\Events\QueryExecuted $query */
            if (\preg_match('/\A.*?\bfrom\s+[`"]?scoped_posts[`"]?(?=\s|\z)/i', $query->sql, $match) !== 1) {
                return;
            }

            $queries[] = $match[0];
        });

        $callback();

        DB::getEventDispatcher()?->forget(QueryExecuted::class);

        return $queries;
    }

    /**
     * Scope the query through the macro, with the manager and context given.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<\Illuminate\Database\Eloquent\Model>  $query
     * @param  string  $action
     * @param  \SineMacula\Laravel\Authorization\AuthorizationManager|null  $manager
     * @param  array<string, mixed>  $context
     *
     * @phpstan-param \Illuminate\Database\Eloquent\Builder<covariant \Illuminate\Database\Eloquent\Model> $query
     *
     * @return \Illuminate\Database\Eloquent\Builder<\Illuminate\Database\Eloquent\Model>
     */
    private static function authorized(Builder $query, string $action, ?AuthorizationManager $manager = null, array $context = []): Builder
    {
        $scoped = $query->whereAuthorized($action, $context, $manager); // @phpstan-ignore method.notFound

        self::assertInstanceOf(Builder::class, $scoped);

        return $scoped;
    }
}
