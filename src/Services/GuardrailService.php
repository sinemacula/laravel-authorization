<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Services;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Administration\ActingContext;
use SineMacula\Laravel\Authorization\Concerns\HasContainerInstance;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
use SineMacula\Laravel\Authorization\Enums\GrantOutcome;
use SineMacula\Laravel\Authorization\Enums\GrantTarget;
use SineMacula\Laravel\Authorization\Events\Guardrail\GuardrailRemoved;
use SineMacula\Laravel\Authorization\Events\Guardrail\GuardrailSet;
use SineMacula\Laravel\Authorization\Exceptions\GuardrailException;
use SineMacula\Laravel\Authorization\Exceptions\InvalidGrantTargetException;
use SineMacula\Laravel\Authorization\Exceptions\UnwrittenGrantException;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Services\Support\GrantScopes;
use SineMacula\Laravel\Authorization\Services\Support\GuardrailAuthority;
use SineMacula\Laravel\Authorization\Services\Support\GuardrailTable;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\InlinePolicies;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\OperationScope;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\PolicyDocument;
use SineMacula\Laravel\Authorization\Support\PolicyPrincipals;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Sets and removes guardrails, on tenants and on the platform (AUTHZ-7.6).
 *
 * A guardrail is a managed policy that caps what any subject may do in its
 * scope: a check passes the guardrail stage only when every guardrail that
 * applies allows it, as the policy's allow statements would, conditions
 * included, and its deny statements deny at the deny stage. A guardrail grants
 * nothing: what passes it is still decided by the allows. A guardrail on a
 * tenant holds in the tenant and its subtree, through the tenant tree
 * (AUTHZ-5.3), and the platform's everywhere; with none, nothing is capped.
 *
 * Every call names the tenant, or null for the platform, and the acting context
 * making the change, which is never optional: there is no trusted guardrail
 * change. Its subject must hold `authorization:guardrail.manage` from above the
 * scope: through a grant held at an ancestor of the tenant that reaches it, or
 * platform-wide, never one held within the tenant itself, and for the platform
 * a platform-wide grant (see `GuardrailAuthority`). The right is decided inside
 * the change's transaction, before anything is read or written, and any other
 * actor is refused with `GuardrailException`, an impersonated one with
 * `AuthorizationException` as `administration.impersonating` unless
 * `authorization:administration.impersonated` is allowed it, so a tenant's own
 * administrators never lift the guardrails their tenant is set under. A removal
 * lifts a cap across the scope's whole subtree, so both rights are weighed
 * across it too, and refused when anything that denies or caps the actor
 * anywhere there could limit them; a set only adds a cap, and is decided from
 * above alone (see `GuardrailAuthority`). The right is decided through
 * `check()` with the guardrails left out, as every check of
 * `authorization:guardrail.manage` is, so no guardrail locks the guardrails:
 * one that does not allow the permission, or whose document cannot be read, a
 * platform guardrail included, is still removed through here. Every other deny
 * and cap that applies to the actor still counts.
 *
 * A scope may have any number of guardrails, a policy at most once in each. A
 * policy one tenant owns is set on that tenant or a tenant below it, and naming
 * any other scope is refused with `GrantScopeMismatchException`. An inline
 * policy is refused with `GuardrailException`, a policy naming `principals`
 * with `ResourcePolicyException`, and a policy whose row is gone with
 * `InvalidGrantTargetException`, each before anything is written. A policy
 * deleted while the guardrail is written is refused with
 * `InvalidGrantTargetException` too, and a guardrail whose row could not be
 * written for another reason with `UnwrittenGrantException`, so a guardrail is
 * only ever reported set, and `GuardrailSet` dispatched, once its row is there.
 * A policy in use as a guardrail is neither edited nor deleted until every
 * guardrail it is has been removed.
 *
 * Every change runs under the concurrency protocol of delegated administration:
 * the actor's authority, the policy's row and the guardrails of the scope and
 * of the scopes above it are locked and pinned before the right is decided and
 * read again once it is allowed, so a right revoked, a policy rewritten or a
 * tenant moved meanwhile has the change tried again, and refused as
 * `administration.conflict` once the first try and every one of the
 * `authorization.administration.retries` retries have conflicted.
 *
 * Every call runs in one transaction on the package's connection, is one
 * operation for the actor, recorded on the row it writes, and dispatches
 * `GuardrailSet` or `GuardrailRemoved` once it commits, only when it changed
 * something. The cached guardrails are invalidated through the version every
 * guardrail entry shares, so the change takes effect on the next check in every
 * worker.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class GuardrailService
{
    use HasContainerInstance;

    /**
     * Set the policy as a guardrail on the tenant, or on the platform when the
     * tenant is null, for the actor, and return what changed: a new guardrail,
     * or nothing when the scope already has it.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext  $actor
     * @return \SineMacula\Laravel\Authorization\Enums\GrantOutcome
     *
     * @throws \Throwable
     */
    public function set(Policy $policy, Model|Reference|null $tenant, ActingContext $actor): GrantOutcome
    {
        $named = GrantScopes::named($tenant);

        $operation = Operation::begin($actor, [PackagePermissions::GUARDRAIL_MANAGE]);

        return OperationScope::run($operation, static function (Operation $operation) use ($actor, $policy, $named): GrantOutcome {
            self::assertPermitted($actor, $policy, $named, true);

            // Read under a lock on the policy's row, so the checks below weigh
            // the document as committed, and an edit or a deletion of the
            // policy made meanwhile waits until the guardrail is there to
            // refuse it.
            $stored = InlinePolicies::storedForUpdate($policy->getKey()) ?? throw new InvalidGrantTargetException('policy', $policy);
            $name   = PolicyDocument::nameOf($stored->getAttribute('name'));

            self::assertSettable($policy, $stored, $name, $named);

            $outcome = self::table($operation, $named)->set(self::key($stored)) ?? throw self::unwritten($stored, $named);

            if ($outcome === GrantOutcome::GRANTED) {
                OperationScope::dispatch(new GuardrailSet($operation, Reference::of($stored), $name, new GrantScope($named)));
            }

            return $outcome;
        }, $actor);
    }

    /**
     * Remove the guardrail the policy is on the tenant, or on the platform when
     * the tenant is null, for the actor, and report whether the scope had it.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext  $actor
     * @return bool
     *
     * @throws \Throwable
     */
    public function remove(Policy $policy, Model|Reference|null $tenant, ActingContext $actor): bool
    {
        $named = GrantScopes::named($tenant);

        $operation = Operation::begin($actor, [PackagePermissions::GUARDRAIL_MANAGE]);

        /** @var bool */
        return OperationScope::run($operation, static function (Operation $operation) use ($actor, $policy, $named): bool {
            self::assertPermitted($actor, $policy, $named, false);

            // A guardrail's policy cannot be deleted from under it, so a policy
            // that is not stored is a guardrail nowhere.
            $stored = InlinePolicies::stored($policy->getKey());

            if ($stored === null || !self::table($operation, $named)->remove(self::key($stored))) {
                return false;
            }

            OperationScope::dispatch(new GuardrailRemoved($operation, Reference::of($stored), PolicyDocument::nameOf($stored->getAttribute('name')), new GrantScope($named)));

            return true;
        }, $actor);
    }

    /**
     * Refuse the actor unless it may change the guardrails of the scope, under
     * the concurrency protocol: the actor's authority, the policy's row and the
     * guardrails of the scope and the scopes above it are locked and pinned
     * before the right is decided, and read again once it is allowed, so the
     * change is tried again rather than made on authority that changed
     * meanwhile. A guardrail set only adds a cap, so it narrows; a removal
     * lifts one across the scope's whole reach (see `GuardrailAuthority`).
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext  $actor
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @param  bool  $isNarrowing
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\DependencyChangedException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\GuardrailException
     * @throws \LogicException
     */
    private static function assertPermitted(ActingContext $actor, Policy $policy, ?Reference $tenant, bool $isNarrowing): void
    {
        $pins = OperationScope::delegatedPins();

        $pins->lockGuardrail($policy, $tenant);

        GuardrailAuthority::assertPermitted($actor, $tenant, $isNarrowing);

        $pins->validate();
    }

    /**
     * Refuse to set the policy as a guardrail on the scope: an inline policy or
     * a policy naming `principals`, as stored, or a policy one tenant owns on
     * any scope but that tenant and the tenants below it.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $stored
     * @param  string  $name
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\GuardrailException
     */
    private static function assertSettable(Policy $policy, Policy $stored, string $name, ?Reference $tenant): void
    {
        if (InlinePolicies::ownerOf($stored) !== null) {
            throw GuardrailException::inline($name);
        }

        PolicyPrincipals::assertAttachableToGrantee($stored);
        GrantScopes::assertGrantableIn(GrantTarget::POLICY, $policy, $tenant);
    }

    /**
     * Return the refusal of a guardrail whose row could not be written: the
     * policy's, when it was deleted while the guardrail was written, else that
     * the guardrail was not written.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $stored
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @return \InvalidArgumentException|\RuntimeException
     */
    private static function unwritten(Policy $stored, ?Reference $tenant): \InvalidArgumentException|\RuntimeException
    {
        if (InlinePolicies::isGone($stored->getKey())) {
            return new InvalidGrantTargetException('policy', $stored);
        }

        return new UnwrittenGrantException('guardrail on ' . ($tenant === null ? 'the platform' : "{$tenant->type}:{$tenant->id}"));
    }

    /**
     * Return the writer of the guardrails of the scope, recording the
     * operation's actor on the row it writes.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Operation  $operation
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @return \SineMacula\Laravel\Authorization\Services\Support\GuardrailTable
     */
    private static function table(Operation $operation, ?Reference $tenant): GuardrailTable
    {
        /** @var string $table */
        $table = config('authorization.tables.guardrails', 'guardrails');

        return new GuardrailTable(AuthorizationConnection::connection(), $table, $tenant, $operation->actor);
    }

    /**
     * Return a policy's key as a string.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @return string
     */
    private static function key(Policy $policy): string
    {
        /** @var int|string $key */
        $key = $policy->getKey();

        return (string) $key;
    }
}
