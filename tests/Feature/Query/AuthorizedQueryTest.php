<?php

declare(strict_types = 1);

namespace Tests\Feature\Query;

use Illuminate\Database\Eloquent\Relations\Relation;
use Illuminate\Database\Query\Builder as QueryBuilder;
use PHPUnit\Framework\Attributes\After;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Exceptions\QueryScopeRefusedException;
use SineMacula\Laravel\Authorization\Query\AuthorizedQuery;
use SineMacula\Laravel\Authorization\Query\Enums\RefusalReason;
use SineMacula\Laravel\Authorization\Query\Refusal;
use Tests\Concerns\ScopesQueries;
use Tests\Fixtures\QueryScoping\ScopedPost;
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
    use ScopesQueries;

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
            throw QueryScopeRefusedException::of('posts:view', 'posts', new Refusal(RefusalReason::TENANT_TREE));
        }));

        self::assertSame([RefusalReason::TENANT_TREE], $refused->reasons());
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
     * Forget the morph map a test set.
     *
     * @return void
     */
    #[After]
    protected function forgetMorphMap(): void
    {
        Relation::morphMap([], false);
    }

    /**
     * Return a scope keeping every row.
     *
     * @return \SineMacula\Laravel\Authorization\Query\AuthorizedQuery
     */
    private static function scope(): AuthorizedQuery
    {
        return AuthorizedQuery::compiled(new ScopedPost, 'posts:view', static fn (): string => '1 = 1');
    }
}
