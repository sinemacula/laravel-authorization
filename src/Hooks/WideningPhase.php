<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Hooks;

use Illuminate\Container\Container;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Administration\OperationGrantee;
use SineMacula\Laravel\Authorization\Config\ConfigValue;
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
 * included, after the hooks the configuration lists (N108), so every hook runs
 * before any lock and any write. Only then does the call enter the concurrency
 * protocol: it locks, reads its records again, rebuilds the grants it writes
 * and decides them, and hands them to `assertCovers()` before writing. The
 * final grants are classified again, this time with locking reads, after every
 * other lock the call takes (see
 * `Administration\DependencyPins::lockCoverage()`): the grantee's own row of
 * each grant, and the grants of the identity and its principals that applied in
 * each tenant, the evidence the hook was skipped or limited on. A locking read
 * sees the latest committed rows, whatever snapshot the transaction reads
 * otherwise, and the rows it finds cannot be revoked until the call commits. A
 * final grant that now widens with no hook run for it, because a grant the
 * classification relied on was revoked and committed meanwhile, say, aborts the
 * try with a dependency conflict: the whole call is tried again from the
 * proposal, and a hook is never called under the package's locks. Only the
 * application's own reads, the identity directory's list and the tenant tree,
 * are read as they stand.
 *
 * A call made inside a transaction the application opened is never tried again
 * there with its hook: the failed try's row locks stay held until that
 * transaction ends, on MySQL even once rolled back to the try's savepoint. A
 * coverage conflict there, and a try that would call the hook again after an
 * earlier try of the call failed there, is thrown as
 * `TransactionConflictException`, for the application to restart its
 * transaction.
 *
 * While the hook runs, every package mutation service refuses (see
 * `OperationScope::whileHookRuns()`). A grant made inside another management
 * call's work, which may already hold the package's locks, cannot run its hook
 * before every lock, so one that widens is refused with `NestedGrantException`
 * rather than written with its hook skipped. With no hook configured or bound
 * (`GrantHooks` holding none), nothing is classified, since there is nothing to
 * call; a binding of the contract to anything that does not implement it is
 * refused, never taken as none. A grant to a role widens no identity's scope
 * and is never classified either.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class WideningPhase
{
    /**
     * Create the phase of a call, inactive when no subject is given.
     *
     * @param  array{\SineMacula\Laravel\Authorization\Support\Operation, \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference}|null  $subject
     * @param  list<string>  $covered
     */
    private function __construct(

        /** The operation the call runs as and the grantee it writes for, or null when no hook runs for it. */
        private ?array $subject = null,

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

        return new self([$operation, $grantee], \array_map(static fn (ProposedGrant $change): string => $change->key(), $widening->changes ?? []));
    }

    /**
     * Throw a dependency conflict when a final grant of the call widens the
     * identity's scope with no hook run for it, classified with locking reads,
     * so the try is rolled back and the call tried again; with no hook run for
     * the call at all, do nothing. The proposal must read the grantee's rows it
     * relies on under the lock too (see `additions()`).
     *
     * @param  \Closure(): list<\SineMacula\Laravel\Authorization\Hooks\ProposedGrant>  $propose
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\DependencyChangedException
     */
    public function assertCovers(\Closure $propose): void
    {
        if ($this->subject === null) {
            return;
        }

        [$operation, $grantee] = $this->subject;

        $widening = WideningClassifier::classify($operation, $grantee, $propose(), isLocked: true);

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
     * so it proposes nothing. Asked to lock, for the check after the locks, the
     * rows held live are read under the lock.
     *
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $kind
     * @param  \DateTimeInterface|null  $expiresAt
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $written
     * @param  \SineMacula\Laravel\Authorization\Services\Support\GrantTable  $table
     * @param  array<string, \Illuminate\Database\Eloquent\Model>  $keep
     * @param  bool  $isLocked
     * @return list<\SineMacula\Laravel\Authorization\Hooks\ProposedGrant>
     */
    public static function additions(GrantTarget $kind, ?\DateTimeInterface $expiresAt, GrantScope $written, GrantTable $table, array $keep, bool $isLocked = false): array
    {
        $live      = $table->live(\array_map(\strval(...), \array_keys($keep)), isLocked: $isLocked);
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
     * refuses; refuse a call made inside another management call's work, and
     * conflict on a try made again inside the application's transaction, which
     * still holds the locks the call's failed try took: the conflict is thrown
     * as `TransactionConflictException` there, for the application to restart
     * its transaction.
     *
     * @param  \SineMacula\Laravel\Authorization\Contracts\GrantHook  $hook
     * @param  \SineMacula\Laravel\Authorization\Hooks\GrantWidening  $widening
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\NestedGrantException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\DependencyChangedException
     */
    private static function call(GrantHook $hook, GrantWidening $widening): void
    {
        if (OperationScope::isNested()) {
            throw new NestedGrantException;
        }

        $conflict = OperationScope::retriedInPlace();

        if ($conflict !== null) {
            throw DependencyChangedException::widening($conflict);
        }

        OperationScope::whileHookRuns(static function () use ($hook, $widening): void {
            $hook->beforeWidening($widening);
        });
    }

    /**
     * Return the bound hook, or null when none is bound or the bound one is the
     * composite holding none, so there is nothing to call; refuse a binding
     * that resolves to anything else, rather than call no hook.
     *
     * When the configuration lists hooks, the hook is wrapped so they run
     * before it, unless it already is (N108): the package extends the contract
     * with them, but Laravel applies no extender to an instance it is handed
     * after the package registers, nor to any hook bound after an instance it
     * extended as the package registered.
     *
     * @return \SineMacula\Laravel\Authorization\Contracts\GrantHook|null
     *
     * @throws \UnexpectedValueException
     */
    private static function hook(): ?GrantHook
    {
        $container = Container::getInstance();

        if (!$container->bound(GrantHook::class)) {
            return null;
        }

        // Read through the container's array access, which promises nothing of
        // what the binding resolves to, so a wrong binding is caught here.
        $hook = $container[GrantHook::class];

        if (!$hook instanceof GrantHook) {
            throw new \UnexpectedValueException('The grant hook bound on ' . GrantHook::class . ' resolves to ' . \get_debug_type($hook) . ', which does not implement it.');
        }

        if (ConfigValue::get('grant_hooks', []) !== []) {
            $hook = ListedGrantHooks::wrap($hook, $container);
        }

        return $hook instanceof GrantHooks && $hook->isEmpty() ? null : $hook;
    }
}
