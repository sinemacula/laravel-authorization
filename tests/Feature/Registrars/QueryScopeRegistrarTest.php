<?php

declare(strict_types = 1);

namespace Tests\Feature\Registrars;

use Illuminate\Container\Container;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Events\QueryExecuted;
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
     * The condition is one nested condition with no bindings after every one of
     * the application's, which Laravel groups first when they hold an `or`, one
     * added after the macro included.
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
     * The leaks the design's critique found in a broader scope are refused:
     * `-0`, a literal `*` key, a record's id, a `retrieved` listener and an
     * overridden `getAttribute()`.
     *
     * @return void
     */
    public function testTheCritiquesLeaksAreRefused(): void
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
