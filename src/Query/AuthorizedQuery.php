<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Query;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Scope;
use Illuminate\Database\Query\Builder as QueryBuilder;
use SineMacula\Laravel\Authorization\Exceptions\QueryScopeRefusedException;
use SineMacula\Laravel\Authorization\Query\Enums\RefusalReason;

/**
 * The scope `whereAuthorized()` puts on a query (AUTHZ-10.1, N64, N68): it
 * keeps exactly the rows of the query's candidate set, before any limit or
 * offset, that `check()` allows, under the state at the instant the query runs.
 *
 * It is compiled when `whereAuthorized()` is called, so a refusal throws there,
 * before the builder is changed, and again every time the query runs, from the
 * state then: Laravel applies a global scope to a clone of the builder for each
 * execution (a page and its count, a chunk, an update), so no decision is ever
 * reused and the builder the application holds never changes. A refusal at
 * execution throws from the call that runs the query.
 *
 * The condition is one nested `where`, holding one raw condition with no
 * bindings, added after every constraint of the application's, which Laravel
 * groups first when they hold an `or`, so the query is the application's
 * constraints and then the authorization's.
 *
 * A guard, run before every execution, refuses a query that would escape the
 * condition: one whose scope was removed after `whereAuthorized()` (remove
 * scopes before calling it), one joined with `or` at the top after the
 * condition, one with a union, and one that selects from anything but the
 * model's table, an alias or a subquery included, which the condition's
 * qualified columns would not name. The nested queries the scope adds are
 * marked on the scope itself, so the guard tells them apart from any other.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @implements \Illuminate\Database\Eloquent\Scope<\Illuminate\Database\Eloquent\Model>
 *
 * @internal
 */
final class AuthorizedQuery implements Scope
{
    /** @var string What the scope is registered on the builder as, unique to the call, so two calls combine. */
    public readonly string $identifier;

    /** @var \WeakMap<\Illuminate\Database\Query\Builder, true> The nested queries the scope has added, while they live. */
    private \WeakMap $markers;

    /**
     * Create a new authorized query scope.
     *
     * @param  string  $action
     * @param  string  $table
     * @param  string  $type
     * @param  \Closure(): string  $compile
     */
    private function __construct(

        /** The action the query is scoped to. */
        private readonly string $action,

        /** The model's table, the only one the query may select from. */
        private readonly string $table,

        /** The model's class, which refusals name. */
        private readonly string $type,

        /** Compiles the condition from the state at the instant it is called. */
        private readonly \Closure $compile,
    ) {
        // Unique among the scopes alive, and a scope lives as long as a builder
        // holds it.
        $this->identifier = 'authorization.authorized:' . \spl_object_hash($this);
        $this->markers    = new \WeakMap;
    }

    /**
     * Return the scope of the model's query, having compiled it once, so a
     * refusal (`QueryScopeRefusedException`) throws now.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @param  string  $action
     * @param  \Closure(): string  $compile
     * @return self
     */
    public static function compiled(Model $model, string $action, \Closure $compile): self
    {
        $compile();

        return new self($action, $model->getTable(), $model::class, $compile);
    }

    /**
     * Add the condition, compiled from the state now, to the query about to
     * run; a refusal (`QueryScopeRefusedException`) throws from the call that
     * runs it.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<\Illuminate\Database\Eloquent\Model>  $builder
     * @param  \Illuminate\Database\Eloquent\Model  $model
     *
     * @phpstan-param \Illuminate\Database\Eloquent\Builder<covariant \Illuminate\Database\Eloquent\Model> $builder
     *
     * @return void
     */
    #[\Override]
    public function apply(Builder $builder, Model $model): void
    {
        $condition = ($this->compile)();

        $builder->getQuery()->whereNested(function (QueryBuilder $nested) use ($condition): void {
            $nested->whereRaw($condition);

            $this->markers[$nested] = true;
        });
    }

    /**
     * Refuse a query the condition could not hold for, before it is scoped: one
     * with a union, or one that selects from anything but the model's table.
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\QueryScopeRefusedException
     */
    public function assertScopable(QueryBuilder $query): void
    {
        $this->refuseWhen(match (true) {
            ($query->unions ?? []) !== []           => RefusalReason::QUERY_UNION,
            $query->from           !== $this->table => RefusalReason::QUERY_FROM,
            default                                 => null,
        });
    }

    /**
     * Refuse, before the query runs, a query that would escape the condition:
     * its scope was removed, it is joined with `or` at the top, it has a union,
     * or it selects from anything but the model's table.
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\QueryScopeRefusedException
     */
    public function guard(QueryBuilder $query): void
    {
        $wheres   = $query->wheres;
        $isMarked = false;
        $hasOr    = false;

        foreach ($wheres as $index => $where) {
            $isMarked = $isMarked || (($where['type'] ?? null) === 'Nested' && isset($this->markers[$where['query']]));

            // The grammar drops the first condition's boolean.
            $hasOr = $hasOr || ($index > 0 && \str_contains((string) ($where['boolean'] ?? ''), 'or'));
        }

        $this->refuseWhen(match (true) {
            !$isMarked => RefusalReason::SCOPE_REMOVED,
            $hasOr     => RefusalReason::QUERY_OR,
            default    => null,
        });
        $this->assertScopable($query);
    }

    /**
     * Throw the refusal for the reason, when there is one.
     *
     * @param  \SineMacula\Laravel\Authorization\Query\Enums\RefusalReason|null  $reason
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\QueryScopeRefusedException
     */
    private function refuseWhen(?RefusalReason $reason): void
    {
        if ($reason === null) {
            return;
        }

        $detail = $reason === RefusalReason::SCOPE_REMOVED ? 'remove global scopes before calling whereAuthorized()' : null;

        throw QueryScopeRefusedException::of($this->action, $this->type, new Refusal($reason, null, null, null, $detail));
    }
}
