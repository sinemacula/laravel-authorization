<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Services;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Administration\ActingContext;
use SineMacula\Laravel\Authorization\Administration\OperationResource;
use SineMacula\Laravel\Authorization\Concerns\HasContainerInstance;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
use SineMacula\Laravel\Authorization\Enums\GrantOutcome;
use SineMacula\Laravel\Authorization\Enums\GrantTarget;
use SineMacula\Laravel\Authorization\Events\Resource\PolicyAttached;
use SineMacula\Laravel\Authorization\Events\Resource\PolicyDetached;
use SineMacula\Laravel\Authorization\Exceptions\InvalidGrantTargetException;
use SineMacula\Laravel\Authorization\Exceptions\InvalidResourceException;
use SineMacula\Laravel\Authorization\Exceptions\UnwrittenGrantException;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Services\Support\GrantScopes;
use SineMacula\Laravel\Authorization\Services\Support\ResourcePolicyTable;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\InlinePolicies;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\OperationScope;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
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
 * is refused with `InvalidResourceException`, as is a record whose key is `*`,
 * which a check on the type alone stands for. A pair names its record without
 * asking the bound resource tenant resolver, since where an attachment holds
 * comes from the call, not from the record's tenant. An inline policy, a policy
 * with an allow statement naming no principals, and a policy whose row is gone
 * are refused before anything is written (see `PolicyPrincipals`). A policy
 * deleted while the attachment is written is refused with
 * `InvalidGrantTargetException` too, and an attachment whose row could not be
 * written for another reason with `UnwrittenGrantException`, so an attachment
 * is only ever reported, and `PolicyAttached` dispatched, once its row is
 * there.
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
 * operation for the acting context the call names, or trusted system work with
 * none (N75), and dispatches `PolicyAttached` or `PolicyDetached` once it
 * commits, only when it changed something, invalidating the resolution cache
 * for the resource's type.
 *
 * A call with an acting context is delegated administration (AUTHZ-11.1): an
 * attachment is decided under `authorization:resource-policy.attach`, and each
 * detachment, of the policy named or of every policy attached to the record,
 * under `authorization:resource-policy.detach`, as the actor, through
 * `check()`, on the change's operation resource (whose grantee is the resource,
 * `*` for its whole type), inside the transaction before anything is written;
 * the first refused throws the decision's `AuthorizationException`, leaving
 * nothing written. An attachment's allows grant without any permission held, to
 * every principal they name, on one record or the whole type, so each
 * principal, the holders of a role a selector names included, must be one the
 * actor administers across the attachment's reach, junior to it and not itself
 * without `authorization:administration.self` (see `Impact`), and the actor
 * must be able to hand out what the policy allows (see `PolicyRoute`);
 * detaching a policy with no deny statement only narrows, and is allowed on its
 * action alone, while detaching one that denies is refused as
 * `administration.unprovable`.
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
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext|null  $actor
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
        ?ActingContext $actor = null,
    ): GrantOutcome {
        $reference = self::resource($resource);
        $named     = new GrantScope(GrantScopes::named($tenant), $application, $includeSubtree);

        $operation = Operation::begin($actor, [PackagePermissions::RESOURCE_POLICY_ATTACH]);

        /** @var \SineMacula\Laravel\Authorization\Enums\GrantOutcome */
        return OperationScope::run($operation, static function (Operation $operation) use ($actor, $policy, $reference, $named): GrantOutcome {
            $stored = self::stored($policy);

            PolicyPrincipals::assertAttachableToResource($stored);

            $owner = GrantScopes::of(GrantTarget::POLICY, $policy, $named->tenant);
            $scope = new GrantScope($owner, $named->application, $named->includeSubtree || $owner === null);

            $actor?->authorizeIn($operation, OperationResource::grant(PackagePermissions::RESOURCE_POLICY_ATTACH, self::granteeOf($reference), $stored, $scope));

            $outcome = self::table($reference, $scope)->attach(self::key($stored)) ?? throw self::unwritten($stored, $reference);

            if ($outcome !== GrantOutcome::UNCHANGED) {
                OperationScope::dispatch(new PolicyAttached($operation, (string) $reference->type, $reference->id, Reference::of($stored), self::name($stored), $scope));
            }

            return $outcome;
        }, $actor);
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
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext|null  $actor
     * @return int
     *
     * @throws \Throwable
     */
    public function detach(Policy $policy, mixed $resource, Model|Reference|null $tenant = null, ?string $application = null, ?ActingContext $actor = null): int
    {
        $reference = self::resource($resource);
        $named     = GrantScopes::named($tenant) ?? Reference::tenantOf($policy);

        $operation = Operation::begin($actor, [PackagePermissions::RESOURCE_POLICY_DETACH]);

        /** @var int */
        return OperationScope::run($operation, static function (Operation $operation) use ($actor, $policy, $reference, $named, $application): int {
            $stored = self::stored($policy);

            $scope = new GrantScope($named, $application);

            $actor?->authorizeIn($operation, OperationResource::revoke(PackagePermissions::RESOURCE_POLICY_DETACH, self::granteeOf($reference), $stored, $scope));

            $detached = self::table($reference, $scope)->detach(self::key($stored));

            if ($detached === null) {
                return 0;
            }

            OperationScope::dispatch(new PolicyDetached($operation, (string) $reference->type, $reference->id, Reference::of($stored), self::name($stored), $detached));

            return 1;
        }, $actor);
    }

    /**
     * Detach every policy attached to the record, in every scope, and return
     * how many attachments were detached, reporting each with `PolicyDetached`:
     * what the pruner does for a record that no longer exists. The attachments
     * of a whole type are never detached this way, so a type is refused with
     * `InvalidResourceException`. For an acting context and a record with
     * nothing attached, the detachment is decided unchanged at platform scope,
     * so its action is decided either way.
     *
     * @param  mixed  $resource
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext|null  $actor
     * @return int
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidResourceException
     * @throws \Throwable
     */
    public function detachAll(mixed $resource, ?ActingContext $actor = null): int
    {
        $reference = self::record($resource);

        /** @var int<0, max> */
        return OperationScope::run(Operation::begin($actor, [PackagePermissions::RESOURCE_POLICY_DETACH]), static function (Operation $operation) use ($actor, $reference): int {
            $attachments = self::attachmentsOf($reference);
            $events      = [];

            $grantee = self::granteeOf($reference);

            $action = PackagePermissions::RESOURCE_POLICY_DETACH;
            $detach = static fn (array $attachment): OperationResource => OperationResource::revoke($action, $grantee, ...$attachment);

            $actor?->authorizeChanges($operation, \array_map($detach, $attachments), OperationResource::unchanged($action, $grantee, null, GrantScope::platform()));

            foreach ($attachments as [$policy, $scope]) {
                $held = self::table($reference, $scope)->detach(self::key($policy));

                if ($held === null) {
                    continue;
                }

                $events[] = new PolicyDetached($operation, (string) $reference->type, $reference->id, Reference::of($policy), self::name($policy), $held);
            }

            OperationScope::dispatch(...$events);

            return \count($events);
        }, $actor);
    }

    /**
     * Return the resource a policy is attached to as the grantee of the change,
     * by its type and key, `*` for its whole type.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceReference  $resource
     * @return \SineMacula\Laravel\Authorization\Support\Reference
     */
    private static function granteeOf(ResourceReference $resource): Reference
    {
        return new Reference((string) $resource->type, $resource->id ?? '*');
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
        $reference = match (true) {
            \is_array($resource)  => ResourceReferences::recordOf($resource),
            \is_string($resource) => self::typeOf($resource),
            default               => ResourceReferences::of($resource),
        };

        if (!self::isAttachable($reference)) {
            throw new InvalidResourceException($resource);
        }

        return $reference;
    }

    /**
     * Return the reference to the type a string names: a model class's morph
     * class, or the string itself; false for an abstract model class, and null
     * for an empty string or one holding a NUL byte.
     *
     * @param  string  $resource
     * @return false|\SineMacula\Laravel\Authorization\Support\ResourceReference|null
     */
    private static function typeOf(string $resource): false|ResourceReference|null
    {
        if (\is_subclass_of($resource, Model::class)) {
            return ResourceReferences::of($resource);
        }

        return $resource === '' || \str_contains($resource, "\0") ? null : ResourceReference::type($resource);
    }

    /**
     * Return the reference to the record a policy is attached to, refusing a
     * whole type as well as anything `resource()` refuses.
     *
     * @param  mixed  $resource
     * @return \SineMacula\Laravel\Authorization\Support\ResourceReference
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidResourceException
     */
    private static function record(mixed $resource): ResourceReference
    {
        $reference = self::resource($resource);

        return $reference->id === null ? throw new InvalidResourceException($resource) : $reference;
    }

    /**
     * Determine whether the reference names a resource a policy can be attached
     * to: a type, and a key unless it is the type alone, each non-empty and
     * within the bytes the table stores, the key never `*`, which a check on
     * the type alone stands for.
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

        return self::isStorable($reference->type) && ($reference->id === null || (self::isStorable($reference->id) && $reference->id !== '*'));
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
        return new ResourcePolicyTable(AuthorizationConnection::connection(), self::tableName(), (string) $resource->type, $resource->id, $scope);
    }

    /**
     * Return each policy attached to the resource, in every scope, with the
     * scope it is attached in.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceReference  $resource
     * @return list<array{\SineMacula\Laravel\Authorization\Models\Policy, \SineMacula\Laravel\Authorization\Support\GrantScope}>
     */
    private static function attachmentsOf(ResourceReference $resource): array
    {
        /** @var list<array{policy_id: string, tenant_type: string|null, tenant_id: string|null, application: string|null}> $rows */
        $rows = AuthorizationConnection::connection()->table(self::tableName())
            ->where('resource_type', $resource->type)
            ->where('resource_id', $resource->id)
            ->get(['policy_id', 'tenant_type', 'tenant_id', 'application'])
            ->map(static fn (object $row): array => (array) $row)
            ->all();

        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Policy> $class */
        $class = config('authorization.models.policy', Policy::class);

        /** @var array<string, \SineMacula\Laravel\Authorization\Models\Policy> $policies */
        $policies    = $class::query()->withoutGlobalScopes()->useWritePdo()->whereKey(\array_column($rows, 'policy_id'))->get()->getDictionary();
        $attachments = [];

        foreach ($rows as $row) {
            $policy = $policies[$row['policy_id']] ?? null;

            if ($policy === null) {
                continue;
            }

            $tenant        = $row['tenant_type'] === null ? null : new Reference($row['tenant_type'], (string) $row['tenant_id']);
            $attachments[] = [$policy, new GrantScope($tenant, $row['application'])];
        }

        return $attachments;
    }

    /**
     * Return the refusal of an attachment whose row could not be written: the
     * policy's, when it was deleted while the attachment was written, else that
     * the attachment was not written.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $stored
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceReference  $resource
     * @return \InvalidArgumentException|\RuntimeException
     */
    private static function unwritten(Policy $stored, ResourceReference $resource): \InvalidArgumentException|\RuntimeException
    {
        if (InlinePolicies::isGone($stored->getKey())) {
            return new InvalidGrantTargetException('policy', $stored);
        }

        return new UnwrittenGrantException('attachment of policy \'' . self::name($stored) . "' to {$resource->identifier}");
    }

    /**
     * Return the resource policies table, as `authorization.tables` names it.
     *
     * @return string
     */
    private static function tableName(): string
    {
        /** @var string */
        return config('authorization.tables.resource_policies', 'resource_policies');
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
