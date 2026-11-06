<?php

declare(strict_types = 1);

namespace Tests\Feature\Query;

use Illuminate\Database\Query\Builder as QueryBuilder;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Exceptions\QueryScopeRefusedException;
use SineMacula\Laravel\Authorization\Query\AuthorizedQuery;
use SineMacula\Laravel\Authorization\Query\Enums\RefusalReason;
use SineMacula\Laravel\Authorization\Query\Refusal;
use Tests\Concerns\ScopesQueries;
use Tests\Fixtures\QueryScoping\ScopedPost;
use Tests\TestCase;

/**
 * Feature tests for the scope `whereAuthorized()` puts on a query: compiled
 * when it is made and at every execution, added as one nested condition, and
 * guarded before every execution.
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
     * The scope is compiled once when it is made, so a refusal throws then, and
     * again each time it is applied, from the state at that instant; two scopes
     * have different identifiers.
     *
     * @return void
     */
    public function testTheScopeIsCompiledWhenMadeAndWhenApplied(): void
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
        self::assertNotSame($scope->identifier, AuthorizedQuery::compiled(new ScopedPost, 'posts:view', static fn (): string => '1 = 1')->identifier);

        $builder = ScopedPost::query();

        $scope->apply($builder, new ScopedPost);
        $scope->apply($builder, new ScopedPost);

        self::assertCount(3, $compiled);

        $wheres = $builder->getQuery()->wheres;

        self::assertCount(2, $wheres);
        self::assertSame(['Nested', 'and'], [$wheres[0]['type'], $wheres[0]['boolean']]);
        self::assertSame([['type' => 'raw', 'sql' => '2 = 2', 'boolean' => 'and']], $wheres[0]['query']->wheres);
        self::assertSame([], $builder->getBindings());

        $refused = self::refusalOf(static fn (): AuthorizedQuery => AuthorizedQuery::compiled(new ScopedPost, 'posts:view', static function (): string {
            throw QueryScopeRefusedException::of('posts:view', 'posts', new Refusal(RefusalReason::TENANT_TREE));
        }));

        self::assertSame([RefusalReason::TENANT_TREE], $refused->reasons());
    }

    /**
     * The guard lets through a query holding the scope's condition, joined with
     * `and`, the first condition's boolean aside, which the grammar drops.
     *
     * @return void
     */
    public function testTheGuardLetsThroughAQueryHoldingTheCondition(): void
    {
        $scope = self::scope();
        $query = ScopedPost::query()->orWhere('title', 'a');

        $scope->apply($query, new ScopedPost);
        $query->where('status', 'live');
        $scope->guard($query->getQuery());

        self::assertCount(3, $query->getQuery()->wheres);
    }

    /**
     * The guard refuses a query whose condition was removed, one joined with
     * `or` after its first condition, one with a union, and one selecting from
     * anything but the model's table.
     *
     * @return void
     */
    public function testTheGuardRefusesAQueryThatWouldEscapeTheCondition(): void
    {
        $scope  = self::scope();
        $guard  = static fn (QueryBuilder $query): array => self::refusalOf(static fn () => $scope->guard($query))->reasons();
        $scoped = static function () use ($scope): QueryBuilder {
            $query = ScopedPost::query();

            $scope->apply($query, new ScopedPost);

            return $query->getQuery();
        };

        self::assertSame([RefusalReason::SCOPE_REMOVED], $guard(ScopedPost::query()->where('title', 'a')->getQuery()));
        $nested = ScopedPost::query()->whereNested(static fn (QueryBuilder $nested): QueryBuilder => $nested->whereRaw('1 = 1'));

        self::assertSame([RefusalReason::SCOPE_REMOVED], $guard($nested->getQuery()));
        self::assertSame([RefusalReason::QUERY_OR], $guard($scoped()->orWhere('title', 'a')));
        self::assertSame([RefusalReason::QUERY_UNION], $guard($scoped()->union(ScopedPost::query()->toBase())));
        self::assertSame([RefusalReason::QUERY_FROM], $guard($scoped()->from('scoped_posts as p')));
        $removed = self::refusalOf(static fn () => $scope->guard(ScopedPost::query()->getQuery()));

        self::assertSame('remove global scopes before calling whereAuthorized()', $removed->refusals[0]->detail);
    }

    /**
     * Before it is scoped, a query with a union, or selecting from anything but
     * the model's table, is refused; any other is not.
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

        self::assertSame(ScopedPost::class, self::refusalOf(static fn () => $scope->assertScopable(ScopedPost::query()->from('other')->getQuery()))->resourceType);
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
