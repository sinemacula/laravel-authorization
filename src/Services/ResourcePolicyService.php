<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Services;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Concerns\HasContainerInstance;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
use SineMacula\Laravel\Authorization\Enums\GrantOutcome;
use SineMacula\Laravel\Authorization\Enums\GrantTarget;
use SineMacula\Laravel\Authorization\Events\Resource\PolicyAttached;
use SineMacula\Laravel\Authorization\Events\Resource\PolicyDetached;
use SineMacula\Laravel\Authorization\Exceptions\InvalidGrantTargetException;
use SineMacula\Laravel\Authorization\Exceptions\InvalidResourceException;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Services\Support\GrantScopes;
use SineMacula\Laravel\Authorization\Services\Support\ResourcePolicyTable;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\InlinePolicies;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\OperationScope;
use SineMacula\Laravel\Authorization\Support\PolicyDocument;
use SineMacula\Laravel\Authorization\Support\PolicyPrincipals;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResourceReference;
use SineMacula\Laravel\Authorization\Support\ResourceReferences;

/**
 * Attaches policies to resources and resource types, and detaches them
 * (AUTHZ-7.3).
 *
 * A resource policy is a managed policy attached to one record of a type, or to
 * the whole type. A check on a record reads the policies attached to it and to
 * its type; a check on the type alone, those attached to the type. Its denies
 * apply to everyone checking the resource; each of its allows names the
 * subjects it applies to in `principals`, by reference or a role by its key,
 * and allows them without their holding any permission, once the tenant stage
 * has admitted the resource and no deny applies.
 *
 * The resource is a saved model (a record of its morph class), a `(type, id)`
 * pair, a resource reference with a type, a model class (its type), or any
 * other string, taken as a morph type; an unsaved model or an opaque identifier
 * is refused with `InvalidResourceException`. An inline policy, a policy with
 * an allow statement naming no principals, and a policy whose row is gone are
 * refused before anything is written (see `PolicyPrincipals`).
 *
 * An attachment holds in a scope as a grant does (AUTHZ-5.1): a policy one
 * tenant owns is attached in that tenant, or a tenant below it that the call
 * names as `$tenant`, and naming any other is refused with
 * `GrantScopeMismatchException`; one the platform owns is attached in the
 * tenant named, else platform-wide. It reaches the tenants below its tenant
 * unless `$includeSubtree` is false, and holds in the application named, else
 * in every application. A detachment finds the attachment in the same scope.
 *
 * Every call runs in one transaction on the package's connection, is one
 * operation for the actor the call names (null for console and system work),
 * and dispatches `PolicyAttached` or `PolicyDetached` once it commits, only
 * when it changed something, invalidating the resolution cache for the
 * resource's type.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class ResourcePolicyService
{
    use HasContainerInstance;

    /**
     * Attach the policy to the resource, a record or a whole type, and return
     * what changed: a new attachment, its reach alone, or nothing.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @param  mixed  $resource
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @param  bool  $includeSubtree
     * @param  string|null  $application
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $actor
     * @return \SineMacula\Laravel\Authorization\Enums\GrantOutcome
     *
     * @throws \Throwable
     */
    public function attach(
        Policy $policy,
        mixed $resource,
        Model|Reference|null $tenant = null,
        bool $includeSubtree = true,
        ?string $application = null,
        Model|Reference|null $actor = null,
    ): GrantOutcome {
        $reference = self::resource($resource);
        $named     = new GrantScope(GrantScopes::named($tenant), $application, $includeSubtree);

        /** @var \SineMacula\Laravel\Authorization\Enums\GrantOutcome */
        return OperationScope::run(Operation::begin($actor), static function (Operation $operation) use ($policy, $reference, $named): GrantOutcome {
            $stored = self::stored($policy);

            PolicyPrincipals::assertAttachableToResource($stored);

            $owner   = GrantScopes::of(GrantTarget::POLICY, $policy, $named->tenant);
            $scope   = new GrantScope($owner, $named->application, $named->includeSubtree || $owner === null);
            $outcome = self::table($reference, $scope)->attach(self::key($stored));

            if ($outcome !== GrantOutcome::UNCHANGED) {
                OperationScope::dispatch(new PolicyAttached($operation, (string) $reference->type, $reference->id, Reference::of($stored), self::name($stored), $scope));
            }

            return $outcome;
        });
    }

    /**
     * Detach the policy from the resource, a record or a whole type, in the
     * scope, and return how many were detached: none when it was not attached
     * there.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @param  mixed  $resource
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @param  string|null  $application
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $actor
     * @return int
     *
     * @throws \Throwable
     */
    public function detach(Policy $policy, mixed $resource, Model|Reference|null $tenant = null, ?string $application = null, Model|Reference|null $actor = null): int
    {
        $reference = self::resource($resource);
        $named     = GrantScopes::named($tenant) ?? Reference::tenantOf($policy);

        /** @var int */
        return OperationScope::run(Operation::begin($actor), static function (Operation $operation) use ($policy, $reference, $named, $application): int {
            $stored = self::stored($policy);
            $scope  = self::table($reference, new GrantScope($named, $application))->detach(self::key($stored));

            if ($scope === null) {
                return 0;
            }

            OperationScope::dispatch(new PolicyDetached($operation, (string) $reference->type, $reference->id, Reference::of($stored), self::name($stored), $scope));

            return 1;
        });
    }

    /**
     * Return the reference to the resource a policy is attached to: a record or
     * a type, each within the bytes the table stores.
     *
     * @param  mixed  $resource
     * @return \SineMacula\Laravel\Authorization\Support\ResourceReference
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidResourceException
     */
    private static function resource(mixed $resource): ResourceReference
    {
        $reference = \is_string($resource) && !\is_subclass_of($resource, Model::class) && $resource !== '' && !\str_contains($resource, "\0")
            ? ResourceReference::type($resource)
            : ResourceReferences::of($resource);

        if (!self::isAttachable($reference)) {
            throw new InvalidResourceException($resource);
        }

        return $reference;
    }

    /**
     * Determine whether the reference names a resource a policy can be attached
     * to: a type, and a key unless it is the type alone, each non-empty and
     * within the bytes the table stores.
     *
     * @param  false|\SineMacula\Laravel\Authorization\Support\ResourceReference|null  $reference
     * @return bool
     *
     * @phpstan-assert-if-true \SineMacula\Laravel\Authorization\Support\ResourceReference $reference
     */
    private static function isAttachable(false|ResourceReference|null $reference): bool
    {
        if (!$reference instanceof ResourceReference || $reference->type === null) {
            return false;
        }

        return self::isStorable($reference->type) && ($reference->id === null || self::isStorable($reference->id));
    }

    /**
     * Determine whether a resource's type or key is non-empty and within the
     * bytes the table stores.
     *
     * @param  string  $value
     * @return bool
     */
    private static function isStorable(string $value): bool
    {
        return $value !== '' && \strlen($value) <= Reference::MAX_BYTES;
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
     * Return the writer of the resource's attachments in the scope.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceReference  $resource
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $scope
     * @return \SineMacula\Laravel\Authorization\Services\Support\ResourcePolicyTable
     */
    private static function table(ResourceReference $resource, GrantScope $scope): ResourcePolicyTable
    {
        /** @var string $table */
        $table = config('authorization.tables.resource_policies', 'resource_policies');

        return new ResourcePolicyTable(AuthorizationConnection::connection(), $table, (string) $resource->type, $resource->id, $scope);
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

    /**
     * Return the name a stored policy is reported under.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @return string
     */
    private static function name(Policy $policy): string
    {
        return PolicyDocument::nameOf($policy->getAttribute('name'));
    }
}
