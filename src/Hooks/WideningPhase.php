<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Hooks;

use Illuminate\Container\Container;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Administration\OperationGrantee;
use SineMacula\Laravel\Authorization\Contracts\GrantHook;
use SineMacula\Laravel\Authorization\Enums\GrantTarget;
use SineMacula\Laravel\Authorization\Exceptions\DependencyChangedException;
use SineMacula\Laravel\Authorization\Exceptions\NestedGrantException;
use SineMacula\Laravel\Authorization\Services\Support\GrantChanges;
use SineMacula\Laravel\Authorization\Services\Support\GrantTable;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\OperationScope;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * The grant hook phase of a grant call (AUTHZ-11.3, N80): the one call point
 * every grant that may widen an identity's scope goes through, trusted and
 * delegated alike, and the one break-glass (AUTHZ-11.7) will go through.
 *
 * A grant call runs its work in the call's transaction (`OperationScope::run`)
 * and, before it reads or locks anything else, hands `before()` a non-locking
 * preliminary proposal of every grant it is about to write. The proposal is
 * classified (see `WideningClassifier`) and, when any grant widens, the bound
 * hook is called once with every widening grant of the call, a batch's
 * included, so every hook runs before any lock and any write. Only then does
 * the call enter the concurrency protocol: it locks, reads its records again,
 * rebuilds the grants it writes and decides them, and hands them to
 * `assertCovers()` before writing. The final grants are classified again, and
 * one that now widens with no hook run for it, because a grant the
 * classification relied on is gone, say, aborts the try with a dependency
 * conflict: the whole call is tried again from the proposal, and a hook is
 * never called under the package's locks. The second classification reads what
 * the first did, unlocked, so it narrows the window rather than close it: an
 * integration whose own invariant must hold across concurrent writes, such as
 * SSO's, serialises them itself.
 *
 * While the hook runs, every package mutation service refuses (see
 * `OperationScope::whileHookRuns()`). A grant made inside another management
 * call's work, which may already hold the package's locks, cannot run its hook
 * before every lock, so one that widens is refused with `NestedGrantException`
 * rather than written with its hook skipped. With no hook configured or bound
 * (`GrantHooks` holding none), nothing is classified, since there is nothing to
 * call; a grant to a role widens no identity's scope and is never classified
 * either.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class WideningPhase
{
    /**
     * Create the phase of a call, inactive when no operation is given.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Operation|null  $operation
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $grantee
     * @param  list<string>  $covered
     */
    private function __construct(

        /** The operation the call runs as, or null when no hook runs for it. */
        private ?Operation $operation = null,

        /** The grantee the call writes for, or null when no hook runs for it. */
        private Model|Reference|null $grantee = null,

        /** The key of each grant the hook was called for. */
        private array $covered = [],
    ) {}

    /**
     * Classify the grants the proposal makes and, when any widens the
     * identity's scope, call the bound hook with them, before the call takes
     * any lock; return the phase, to check the call's final grants against.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Operation  $operation
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  \Closure(): list<\SineMacula\Laravel\Authorization\Hooks\ProposedGrant>  $propose
     * @return self
     *
     * @throws \Throwable
     */
    public static function before(Operation $operation, Model|Reference $grantee, \Closure $propose): self
    {
        $hook = self::hook();

        if ($hook === null || OperationGrantee::isRole(Reference::of($grantee))) {
            return new self;
        }

        $widening = WideningClassifier::classify($operation, $grantee, $propose());

        if ($widening !== null) {
            self::call($hook, $widening);
        }

        return new self($operation, $grantee, \array_map(static fn (ProposedGrant $change): string => $change->key(), $widening->changes ?? []));
    }

    /**
     * Throw a dependency conflict when a final grant of the call widens the
     * identity's scope with no hook run for it, so the try is rolled back and
     * the call tried again; with no hook run for the call at all, do nothing.
     *
     * @param  \Closure(): list<\SineMacula\Laravel\Authorization\Hooks\ProposedGrant>  $propose
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\DependencyChangedException
     */
    public function assertCovers(\Closure $propose): void
    {
        if ($this->operation === null || $this->grantee === null) {
            return;
        }

        $widening = WideningClassifier::classify($this->operation, $this->grantee, $propose());

        foreach ($widening->changes ?? [] as $change) {
            if (!\in_array($change->key(), $this->covered, true)) {
                throw DependencyChangedException::widening();
            }
        }
    }

    /**
     * Return the grants a sync proposes: each target it keeps that the grantee
     * does not hold live in the written scope, a new grant or the re-arm of an
     * expired one, with the sync's expiry. A target held live is left as it is,
     * so it proposes nothing.
     *
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $kind
     * @param  \DateTimeInterface|null  $expiresAt
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $written
     * @param  \SineMacula\Laravel\Authorization\Services\Support\GrantTable  $table
     * @param  array<string, \Illuminate\Database\Eloquent\Model>  $keep
     * @return list<\SineMacula\Laravel\Authorization\Hooks\ProposedGrant>
     */
    public static function additions(GrantTarget $kind, ?\DateTimeInterface $expiresAt, GrantScope $written, GrantTable $table, array $keep): array
    {
        $live      = $table->live(\array_map(\strval(...), \array_keys($keep)));
        $proposals = [];

        foreach ($keep as $model) {
            if (\in_array(GrantChanges::key($model), $live, true)) {
                continue;
            }

            $proposals[] = ProposedGrant::of($kind, $model, $written, $expiresAt);
        }

        return $proposals;
    }

    /**
     * Call the hook with the widening, while every package mutation service
     * refuses; refuse a call made inside another management call's work.
     *
     * @param  \SineMacula\Laravel\Authorization\Contracts\GrantHook  $hook
     * @param  \SineMacula\Laravel\Authorization\Hooks\GrantWidening  $widening
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\NestedGrantException
     */
    private static function call(GrantHook $hook, GrantWidening $widening): void
    {
        if (OperationScope::isNested()) {
            throw new NestedGrantException;
        }

        OperationScope::whileHookRuns(static function () use ($hook, $widening): void {
            $hook->beforeWidening($widening);
        });
    }

    /**
     * Return the bound hook, or null when none is bound or the bound one is the
     * composite holding none, so there is nothing to call.
     *
     * @return \SineMacula\Laravel\Authorization\Contracts\GrantHook|null
     */
    private static function hook(): ?GrantHook
    {
        $container = Container::getInstance();
        $hook      = $container->bound(GrantHook::class) ? $container->make(GrantHook::class) : null;

        return !$hook instanceof GrantHook || ($hook instanceof GrantHooks && $hook->isEmpty()) ? null : $hook;
    }
}
