<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Scopes;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Scope;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Exceptions\QueryScopeRefusedException;
use SineMacula\Laravel\Authorization\Query\Enums\RefusalReason;
use SineMacula\Laravel\Authorization\Query\Reentrancy;
use SineMacula\Laravel\Authorization\Query\Refusal;

/**
 * A model-level scope that keeps every query of the model to the rows the
 * current subject may take the action on (AUTHZ-10.1), added in the model's
 * `booted()`:
 *
 *     protected static function booted(): void
 *     {
 *         static::addGlobalScope(new AuthorizedScope('posts:view'));
 *     }
 *
 * It behaves exactly as `whereAuthorized()` does, sharing its compiler: each
 * time a query of the model runs, it is compiled from the state then, with no
 * decision cached, for the subject `check()` would decide about then; the rows
 * it keeps are those of the query's candidate set, before any limit or offset,
 * that `check()` allows; a refusal (`QueryScopeRefusedException`) throws from
 * the call that runs the query; and its condition is grouped apart from the
 * query's own constraints and guarded as theirs is.
 *
 * Opting out is the application's explicit choice:
 * `withoutGlobalScope(AuthorizedScope::class)` removes it, and the query runs
 * unscoped, with no refusal; removing a `whereAuthorized()` scope, by contrast,
 * refuses (`scope_removed`), since that scope was asked for on the query.
 *
 * It must never be on the subject's model, nor on a model the decision reads
 * (the grants, roles, policies and tenants): a query of such a model run while
 * a scope is being decided, or one of the subject's own model, refuses
 * (`reentrant`), rather than recursing or reading the decision's sources
 * through itself.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @implements \Illuminate\Database\Eloquent\Scope<\Illuminate\Database\Eloquent\Model>
 */
final readonly class AuthorizedScope implements Scope
{
    /**
     * Create a new model-level authorized scope.
     *
     * @param  string  $action
     * @param  array<string, mixed>  $context
     */
    public function __construct(

        /** The action every query of the model is scoped to. */
        private string $action,

        /** The context every check is given, held under `input`. */
        private array $context = [],
    ) {}

    /**
     * Scope the query about to run to the rows the current subject may take the
     * action on, refusing from the call that runs it.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<\Illuminate\Database\Eloquent\Model>  $builder
     * @param  \Illuminate\Database\Eloquent\Model  $model
     *
     * @phpstan-param \Illuminate\Database\Eloquent\Builder<covariant \Illuminate\Database\Eloquent\Model> $builder
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\QueryScopeRefusedException
     */
    #[\Override]
    public function apply(Builder $builder, Model $model): void
    {
        if (Reentrancy::isDeciding()) {
            $this->refuseReentrant($model);
        }

        Reentrancy::guarded(function () use ($builder, $model): void {
            $manager = AuthorizationManager::instance() ?? throw new \LogicException('An AuthorizedScope needs the authorization manager, which is not bound.');
            $subject = $manager->currentSubject();

            if ($subject !== null && ($subject->subject::class === $model::class || ($subject->identity !== null && $subject->identity::class === $model::class))) {
                $this->refuseReentrant($model);
            }

            // The scope's guard and its condition refuse a query they cannot
            // hold for, as they do for `whereAuthorized()`.
            $manager->queryScope($model, $this->action, $this->context)->apply($builder, $model);
        });
    }

    /**
     * Refuse the query as one of a model the decision itself reads.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @return never
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\QueryScopeRefusedException
     */
    private function refuseReentrant(Model $model): never
    {
        throw QueryScopeRefusedException::of($this->action, $model->getMorphClass(), new Refusal(RefusalReason::REENTRANT, null, null, $model::class));
    }
}
