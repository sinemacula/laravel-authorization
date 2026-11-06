<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Services;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Concerns\HasContainerInstance;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
use SineMacula\Laravel\Authorization\Enums\GrantOutcome;
use SineMacula\Laravel\Authorization\Enums\GrantTarget;
use SineMacula\Laravel\Authorization\Events\Identity\BoundaryRemoved;
use SineMacula\Laravel\Authorization\Events\Identity\BoundarySet;
use SineMacula\Laravel\Authorization\Exceptions\BoundaryException;
use SineMacula\Laravel\Authorization\Exceptions\InvalidGranteeException;
use SineMacula\Laravel\Authorization\Exceptions\InvalidGrantTargetException;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\Support\BoundaryTable;
use SineMacula\Laravel\Authorization\Services\Support\GrantScopes;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\InlinePolicies;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\OperationScope;
use SineMacula\Laravel\Authorization\Support\PolicyDocument;
use SineMacula\Laravel\Authorization\Support\PolicyPrincipals;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Sets, replaces and removes the permission boundaries of principals and
 * identities (AUTHZ-7.4).
 *
 * A boundary is a managed policy that caps what its grantee may do: a check
 * about a subject passes the boundary stage only when every boundary of its
 * principal and of its identity that applies allows it, as the policy's allow
 * statements would, conditions included, and its deny statements deny at the
 * deny stage. A boundary grants nothing: what passes it is still decided by the
 * allows. With no boundary, nothing is capped.
 *
 * A grantee has at most one boundary per scope (AUTHZ-5.1): platform-wide, or
 * one tenant, reaching the tenants below it unless `$includeSubtree` is false.
 * Setting a boundary where the grantee has one replaces it; every boundary
 * whose scope covers the tenant a check is decided in applies, so a tenant's
 * boundary never replaces the platform's. A policy one tenant owns is set in
 * that tenant, or a tenant below it that the call names, and naming any other
 * is refused with `GrantScopeMismatchException`; one the platform owns is set
 * in the tenant named, else platform-wide. A removal finds the boundary in the
 * tenant named, else platform-wide.
 *
 * The grantee is a saved model or a reference with a type and a key, else
 * `InvalidGranteeException` is thrown; a role is refused with
 * `BoundaryException`, since a boundary caps a principal or an identity. An
 * inline policy is refused with `BoundaryException`, a policy naming
 * `principals` with `ResourcePolicyException`, and a policy whose row is gone
 * with `InvalidGrantTargetException`, each before anything is written. A policy
 * in use as a boundary cannot be deleted until the boundary is removed.
 *
 * Every call runs in one transaction on the package's connection, is one
 * operation for the actor the call names (null for console and system work),
 * recorded on the row it writes, and dispatches `BoundarySet` (carrying the
 * policy it replaced, when it replaced one) or `BoundaryRemoved` once it
 * commits, only when it changed something. The grantee's cached resolutions are
 * invalidated through its version, as a grant's are, so the change takes effect
 * on the next check in every worker.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class BoundaryService
{
    use HasContainerInstance;

    /**
     * Set the policy as the grantee's boundary in the scope, replacing any it
     * has there, and return what changed: a new boundary, a replaced one, its
     * reach alone, or nothing.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @param  bool  $includeSubtree
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $actor
     * @return \SineMacula\Laravel\Authorization\Enums\GrantOutcome
     *
     * @throws \Throwable
     */
    public function set(
        Model|Reference $grantee,
        Policy $policy,
        Model|Reference|null $tenant = null,
        bool $includeSubtree = true,
        Model|Reference|null $actor = null,
    ): GrantOutcome {
        $reference = self::grantee($grantee);
        $named     = GrantScopes::named($tenant);

        /** @var \SineMacula\Laravel\Authorization\Enums\GrantOutcome */
        return OperationScope::run(Operation::begin($actor), static function (Operation $operation) use ($reference, $policy, $named, $includeSubtree): GrantOutcome {
            $stored = self::stored($policy);
            $name   = PolicyDocument::nameOf($stored->getAttribute('name'));

            self::assertSettable($stored, $name, $reference);

            $owner                = GrantScopes::of(GrantTarget::POLICY, $policy, $named);
            $scope                = new GrantScope($owner, null, $includeSubtree || $owner === null);
            [$outcome, $replaced] = self::table($reference, $operation, $scope)->set(self::key($stored));

            if ($outcome !== GrantOutcome::UNCHANGED) {
                $previous = $replaced === null ? null : new Reference($stored->getMorphClass(), $replaced);

                OperationScope::dispatch(new BoundarySet($operation, $reference, Reference::of($stored), $name, $scope, $previous));
            }

            return $outcome;
        });
    }

    /**
     * Remove the grantee's boundary in the scope, and report whether it had one
     * there.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $actor
     * @return bool
     *
     * @throws \Throwable
     */
    public function remove(Model|Reference $grantee, Model|Reference|null $tenant = null, Model|Reference|null $actor = null): bool
    {
        $reference = self::grantee($grantee);
        $named     = GrantScopes::named($tenant);

        /** @var bool */
        return OperationScope::run(Operation::begin($actor), static function (Operation $operation) use ($reference, $named): bool {
            $removed = self::table($reference, $operation, new GrantScope($named))->remove();

            if ($removed !== null) {
                OperationScope::dispatch(self::removedEvent($operation, $reference, ...$removed));
            }

            return $removed !== null;
        });
    }

    /**
     * Remove the grantee's boundaries in every scope, inside the caller's
     * operation, and return a `BoundaryRemoved` for each, for the caller to
     * dispatch with its own: what revoking everything a deleted grantee held
     * does.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  \SineMacula\Laravel\Authorization\Support\Operation  $operation
     * @return list<\SineMacula\Laravel\Authorization\Events\Identity\BoundaryRemoved>
     *
     * @internal
     */
    public static function removeEverywhere(Reference $grantee, Operation $operation): array
    {
        $events = [];

        foreach (self::table($grantee, $operation, GrantScope::platform())->removeEverywhere() as [$policy, $scope]) {
            $events[] = self::removedEvent($operation, $grantee, $policy, $scope);
        }

        return $events;
    }

    /**
     * Return the reference to the grantee, before the call's transaction opens,
     * once it is known to be one a boundary can be written for: a saved model
     * with a key, or a reference with a type and a key.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @return \SineMacula\Laravel\Authorization\Support\Reference
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidGranteeException
     */
    private static function grantee(Model|Reference $grantee): Reference
    {
        $reference = Reference::of($grantee);

        if ($reference->type === '' || $reference->id === '' || ($grantee instanceof Model && !$grantee->exists)) {
            throw new InvalidGranteeException($grantee);
        }

        return $reference;
    }

    /**
     * Refuse to set the policy, as stored, as the grantee's boundary: an inline
     * policy, a policy naming `principals`, or any policy for a role.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $stored
     * @param  string  $name
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\BoundaryException
     */
    private static function assertSettable(Policy $stored, string $name, Reference $grantee): void
    {
        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Role> $roleClass */
        $roleClass = config('authorization.models.role', Role::class);

        if ($grantee->type === (new $roleClass)->getMorphClass()) {
            throw BoundaryException::role($name, $grantee);
        }

        if (InlinePolicies::ownerOf($stored) !== null) {
            throw BoundaryException::inline($name);
        }

        PolicyPrincipals::assertAttachableToGrantee($stored);
    }

    /**
     * Read the policy as stored, refusing one whose row is gone.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @return \SineMacula\Laravel\Authorization\Models\Policy
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidGrantTargetException
     */
    private static function stored(Policy $policy): Policy
    {
        return InlinePolicies::stored($policy->getKey()) ?? throw new InvalidGrantTargetException('policy', $policy);
    }

    /**
     * Return the event of the removal of the boundary that was the policy with
     * the key, in the scope, naming the policy as it is stored.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Operation  $operation
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  string  $policy
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $scope
     * @return \SineMacula\Laravel\Authorization\Events\Identity\BoundaryRemoved
     */
    private static function removedEvent(Operation $operation, Reference $grantee, string $policy, GrantScope $scope): BoundaryRemoved
    {
        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Policy> $class */
        $class = config('authorization.models.policy', Policy::class);

        // A boundary's policy cannot be deleted from under it, so it is read.
        $name = PolicyDocument::nameOf(InlinePolicies::stored($policy)?->getAttribute('name'));

        return new BoundaryRemoved($operation, $grantee, new Reference((new $class)->getMorphClass(), $policy), $name, $scope);
    }

    /**
     * Return the writer of the grantee's boundary in the scope, recording the
     * operation's actor on the row it writes.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  \SineMacula\Laravel\Authorization\Support\Operation  $operation
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $scope
     * @return \SineMacula\Laravel\Authorization\Services\Support\BoundaryTable
     */
    private static function table(Reference $grantee, Operation $operation, GrantScope $scope): BoundaryTable
    {
        /** @var string $table */
        $table = config('authorization.tables.authorizable_boundaries', 'authorizable_boundaries');

        return new BoundaryTable(AuthorizationConnection::connection(), $table, $grantee, $scope->tenant, $scope->includeSubtree, $operation->actor);
    }

    /**
     * Return a stored policy's key as a string.
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
