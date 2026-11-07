<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Registrars;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Query\Grammars\Grammar;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Query\AuthorizedQuery;

/**
 * Registers the `whereAuthorized()` macro on every Eloquent builder
 * (AUTHZ-10.1):
 *
 *     Post::query()->whereAuthorized('posts:view');
 *     Post::query()->whereAuthorized('posts:view', ['post' => …], Authorization::forUser($user));
 *
 * It keeps exactly the rows of the query's candidate set, before any limit or
 * offset, that `check()` would allow the subject on, with the same context, for
 * the record loaded with every column, whatever columns the query selects,
 * under the state at the instant the query runs, or throws
 * `QueryScopeRefusedException` when it cannot prove that (AUTHZ-10.2). The
 * subject is the one `check()` decides about: the current manager's, or that of
 * the manager given, a scoped clone from `for()`, `forUser()`, `withPolicies()`
 * or `capped()` included. It only adds a constraint, never running a query of
 * its own on the model's table, so the application's filters, ordering, selects
 * and pagination keep working. It is called on the query that runs: inside a
 * `where` group or a relation's definition it refuses when the query runs.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class QueryScopeRegistrar
{
    /** @var string The name of the macro. */
    public const string MACRO = 'whereAuthorized';

    /**
     * Register the macro, and the grammar's macro that compiles the condition
     * it adds.
     *
     * @return void
     */
    public function register(): void
    {
        Grammar::macro(AuthorizedQuery::GRAMMAR_MACRO, [AuthorizedQuery::class, 'compileWhere']);

        Builder::macro(self::MACRO, function (string $action, array $context = [], ?AuthorizationManager $authorization = null): Builder {
            /** @var \Illuminate\Database\Eloquent\Builder<\Illuminate\Database\Eloquent\Model> $this */
            /** @var array<string, mixed> $context */
            return QueryScopeRegistrar::scope($this, $action, $context, $authorization);
        });
    }

    /**
     * Scope the builder to the rows the subject may take the action on: the
     * scope is compiled now, so a refusal throws before the builder changes,
     * then holds its place on the builder and is registered on it, to be
     * compiled again each time the query runs.
     *
     * @template TModel of \Illuminate\Database\Eloquent\Model
     *
     * @param  \Illuminate\Database\Eloquent\Builder<TModel>  $builder
     * @param  string  $action
     * @param  array<string, mixed>  $context
     * @param  \SineMacula\Laravel\Authorization\AuthorizationManager|null  $authorization
     * @return \Illuminate\Database\Eloquent\Builder<TModel>
     *
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\QueryScopeRefusedException
     */
    public static function scope(Builder $builder, string $action, array $context = [], ?AuthorizationManager $authorization = null): Builder
    {
        $scope = self::manager($authorization)->queryScope($builder->getModel(), $action, $context);

        $scope->assertScopable($builder->getQuery());
        $scope->holdPlaceOn($builder->getQuery());

        return $builder->withGlobalScope($scope->identifier, $scope);
    }

    /**
     * Return the manager given, or the bound one.
     *
     * @param  \SineMacula\Laravel\Authorization\AuthorizationManager|null  $authorization
     * @return \SineMacula\Laravel\Authorization\AuthorizationManager
     *
     * @throws \LogicException
     */
    private static function manager(?AuthorizationManager $authorization): AuthorizationManager
    {
        return $authorization ?? AuthorizationManager::instance() ?? throw new \LogicException('whereAuthorized() needs the authorization manager, which is not bound.');
    }
}
