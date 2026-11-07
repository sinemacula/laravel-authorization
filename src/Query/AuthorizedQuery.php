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
 * The scope `whereAuthorized()` puts on a query, and the model-level
 * `AuthorizedScope` applies to each query of its model (AUTHZ-10.1, N64, N68):
 * it keeps exactly the rows of the query's candidate set, before any limit or
 * offset, that `check()` would allow on the record loaded with every column,
 * under the state at the instant the query runs.
 *
 * It is compiled when `whereAuthorized()` is called, so a refusal throws there,
 * before the builder is changed, and again every time the query is compiled to
 * SQL to run, from the state then (a page and its count, a chunk, an update,
 * and a query the builder is passed to whole, as `whereExists()` and
 * `whereHas()` take it), so no decision is ever reused. A refusal at execution
 * throws from the call that runs the query.
 *
 * Every compile is marked as deciding a query scope (`Reentrancy`), so a
 * model-level scope (`Scopes\AuthorizedScope`) applied while it decides refuses
 * rather than recursing.
 *
 * The call holds the scope's place on the builder with a condition of its own
 * type, which the grammar compiles through a macro; where the scope is never
 * applied (it was removed, or the builder was nested in a `where` group, merged
 * into a relation's existence query or run past its scopes) that place reaches
 * the grammar and refuses, so the condition is never silently lost. When the
 * scope is applied, to the clone of the builder Laravel makes for each
 * execution, it takes its place out, groups every other constraint of the query
 * in one nested `where` and adds its condition after it, joined with `and`: an
 * `or`, or a raw condition holding one, cannot reach past the group, and a
 * comment in a raw condition leaves the group unclosed, an SQL error.
 *
 * A guard, run before the query is compiled, groups again any constraint added
 * since, and refuses a query that would escape the condition: one whose
 * condition was taken out, one joined with `or` at the top after it, one with a
 * union, and one that selects from anything but the model's table, an alias or
 * a subquery included, which the condition's qualified columns would not name.
 * The grammar, compiling the condition last of all, refuses the same, and
 * anything else added outside the group since the guard ran. A base query taken
 * with `toBase()` is decided afresh each time it runs, and refused once
 * widened.
 *
 * A query taken into another as SQL text (`whereIn()`, `fromSub()`,
 * `joinSub()`, `selectSub()`, `insertUsing()`, a `withCount()` or
 * `withExists()` constraint, `has()` with a count) is compiled when it is taken
 * in, so the other query reuses that decision each time it runs: Laravel gives
 * no sign that a compile is for such a text, so this one shape cannot be
 * refused.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @implements \Illuminate\Database\Eloquent\Scope<\Illuminate\Database\Eloquent\Model>
 *
 * @internal
 */
final readonly class AuthorizedQuery implements Scope
{
    /** @var string The type of the condition the scope adds, which the grammar compiles through its macro. */
    public const string WHERE_TYPE = 'AuthorizedScope';

    /** @var string The grammar macro that compiles the scope's condition, named as the grammar calls it. */
    public const string GRAMMAR_MACRO = 'where' . self::WHERE_TYPE;

    /** @var string What the scope is registered on the builder as, unique to the call, so two calls combine. */
    public string $identifier;

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
        private string $action,

        /** The model's table, the only one the query may select from. */
        private string $table,

        /** The model's morph type, which refusals name. */
        private string $type,

        /** Compiles the condition from the state at the instant it is called. */
        private \Closure $compile,
    ) {
        // Unique among the scopes alive, and a scope lives as long as a builder
        // holds it.
        $this->identifier = 'authorization.authorized:' . \spl_object_hash($this);
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
        Reentrancy::guarded($compile);

        return new self($action, $model->getTable(), $model->getMorphClass(), $compile);
    }

    /**
     * Compile the condition of a scope, as the grammar's macro: refuse when the
     * scope was never applied, else compile it from the state now.
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @param  array<array-key, mixed>  $where
     * @return string
     *
     * @throws \LogicException
     */
    public static function compileWhere(QueryBuilder $query, array $where): string
    {
        $scope = $where['scope'] ?? null;

        if (!$scope instanceof self) {
            throw new \LogicException('A whereAuthorized() condition names no scope.');
        }

        return $scope->conditionIn($query, ($where['applied'] ?? null) === true);
    }

    /**
     * Hold the scope's place on the builder's query, which refuses if it is
     * ever compiled, so the query refuses unless the scope is applied.
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @return void
     */
    public function holdPlaceOn(QueryBuilder $query): void
    {
        $query->wheres[] = $this->where(false);
    }

    /**
     * Take the scope's place out of the query about to run, group every other
     * constraint, add the condition after them and guard the query.
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
        $query = $builder->getQuery();

        $query->wheres = \array_values(\array_filter($query->wheres, fn (array $where): bool => !$this->isPlaceOf($where)));

        self::group($query);

        $query->wheres[] = $this->where(true);

        $query->beforeQuery($this->guard(...));
    }

    /**
     * Refuse a query the condition could not hold for: one with a union, or one
     * that selects from anything but the model's table.
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
     * Before the query is compiled, refuse it when it would escape the
     * condition (its condition was taken out, it has a union, selects from
     * anything but the model's table, or is joined with `or` at the top), else
     * group every constraint added since the scope was applied with the others.
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\QueryScopeRefusedException
     */
    public function guard(QueryBuilder $query): void
    {
        $this->assertScopable($query);
        $this->refuseWhen($this->isAppliedIn($query) ? self::escapeOf($query, true) : RefusalReason::SCOPE_REMOVED);

        self::group($query);
    }

    /**
     * Return the condition, compiled from the state now, for the query the
     * grammar compiles, refusing when the scope was never applied or when the
     * query would escape the condition.
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @param  bool  $isApplied
     * @return string
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\QueryScopeRefusedException
     */
    private function conditionIn(QueryBuilder $query, bool $isApplied): string
    {
        $this->refuseWhen($isApplied ? self::escapeOf($query, false) : RefusalReason::SCOPE_REMOVED);
        $this->assertScopable($query);

        return '(' . Reentrancy::guarded($this->compile) . ')';
    }

    /**
     * Return why the query's constraints would escape the condition, or null
     * when they would not: one at the top after the first is joined with `or`;
     * or, once grouped, one at the top is neither a scope's condition nor a
     * nested group.
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @param  bool  $isGuarding
     * @return \SineMacula\Laravel\Authorization\Query\Enums\RefusalReason|null
     */
    private static function escapeOf(QueryBuilder $query, bool $isGuarding): ?RefusalReason
    {
        $reason = null;

        foreach (\array_values($query->wheres) as $index => $where) {
            // The grammar drops the first condition's boolean.
            $isOr    = $index > 0   && \is_string($where['boolean'] ?? null) && \str_contains($where['boolean'], 'or');
            $isLoose = !$isGuarding && !self::isOurs($where) && ($where['type'] ?? null) !== 'Nested';

            $reason ??= match (true) {
                $isOr    => RefusalReason::QUERY_OR,
                $isLoose => RefusalReason::QUERY_CHANGED,
                default  => null,
            };
        }

        return $reason;
    }

    /**
     * Put every constraint of the query that is not a scope's condition in one
     * nested group, with the bindings they hold, followed by the conditions of
     * the scopes in the order they were added.
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @return void
     */
    private static function group(QueryBuilder $query): void
    {
        $ours      = \array_values(\array_filter($query->wheres, self::isOurs(...)));
        $others    = \array_values(\array_filter($query->wheres, static fn (array $where): bool => !self::isOurs($where)));
        $isGrouped = \count($others) === 1 && ($others[0]['type'] ?? null) === 'Nested' && ($others[0]['boolean'] ?? null) === 'and';

        if ($others === [] || $isGrouped) {
            $query->wheres = [...$others, ...$ours];

            return;
        }

        // A scope's condition holds no binding, so the group holds every one of
        // the query's, in order.
        $group = $query->forNestedWhere();

        $group->wheres            = $others;
        $group->bindings['where'] = $query->bindings['where'];

        $query->wheres = [['type' => 'Nested', 'query' => $group, 'boolean' => 'and'], ...$ours];
    }

    /**
     * Determine whether a constraint is a scope's condition or place.
     *
     * @param  array<array-key, mixed>  $where
     * @return bool
     */
    private static function isOurs(array $where): bool
    {
        return ($where['type'] ?? null) === self::WHERE_TYPE;
    }

    /**
     * Determine whether the scope's condition is at the top of the query.
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @return bool
     */
    private function isAppliedIn(QueryBuilder $query): bool
    {
        $conditions = \array_filter($query->wheres, fn (array $where): bool => self::isOurs($where) && ($where['scope'] ?? null) === $this && ($where['applied'] ?? null) === true);

        return $conditions !== [];
    }

    /**
     * Determine whether a constraint is this scope's place.
     *
     * @param  array<array-key, mixed>  $where
     * @return bool
     */
    private function isPlaceOf(array $where): bool
    {
        return self::isOurs($where) && ($where['scope'] ?? null) === $this && ($where['applied'] ?? null) === false;
    }

    /**
     * Return the scope's condition, or its place when it is not applied.
     *
     * @param  bool  $isApplied
     * @return array{type: string, scope: self, applied: bool, boolean: string}
     */
    private function where(bool $isApplied): array
    {
        return ['type' => self::WHERE_TYPE, 'scope' => $this, 'applied' => $isApplied, 'boolean' => 'and'];
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

        $detail = $reason === RefusalReason::SCOPE_REMOVED ? 'call whereAuthorized() on the query that runs, after removing its global scopes' : null;

        throw QueryScopeRefusedException::of($this->action, $this->type, new Refusal($reason, null, null, null, $detail));
    }
}
