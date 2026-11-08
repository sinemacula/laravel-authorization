<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Contracts;

use SineMacula\Laravel\Authorization\Hooks\GrantWidening;

/**
 * Grant hook contract (AUTHZ-11.3, N80).
 *
 * Before a grant that widens an identity's scope is written, the grant service
 * calls the bound hook with the proposed widening, inside the call's
 * transaction and before the package takes any lock of its own for the call.
 * Under the suite it is bound to `laravel-sso`'s scope widening (AUTHZ-14.2).
 *
 * A hook may only veto: it refuses by throwing, `GrantRefusedException` for a
 * refusal it means, or any other exception, and the whole call rolls back with
 * nothing written and no event dispatched. Returning means only that the hook
 * lets the call go on; it never authorises anything, and every delegated
 * decision is still made after it. A hook never changes the grant, and every
 * package mutation service refuses while a hook runs, with
 * `GrantHookRecursionException`; read-only queries, `GrantScopeQuery` among
 * them, stay allowed.
 *
 * A hook may do the application's own transactional preparation on the
 * package's connection: it rolls back with the grant. A database concurrency
 * error that preparation meets is handled as any concurrency error is: tried
 * again, hook included, when the call opened the transaction, else thrown as
 * `TransactionConflictException`. A hook may run more than once for one call,
 * since a call that conflicts is tried again from the start, so nothing that
 * leaves the transaction belongs in it: no email, no remote call and no queued
 * work. The events dispatched once the call commits are the place for those. A
 * raw Eloquent write on the package's models is not refused while a hook runs,
 * but is the application's responsibility and belongs in no hook.
 *
 * Exactly one hook is bound. The default is `Hooks\GrantHooks`, the ordered
 * composite of the classes `authorization.grant_hooks` lists, which with none
 * listed does nothing; an application binds its own on the contract instead.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface GrantHook
{
    /**
     * Inspect the widening the grant call proposes, and throw to refuse it.
     *
     * @param  \SineMacula\Laravel\Authorization\Hooks\GrantWidening  $widening
     * @return void
     *
     * @throws \Throwable
     */
    public function beforeWidening(GrantWidening $widening): void;
}
