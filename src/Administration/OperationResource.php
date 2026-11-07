<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Administration;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableResource;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResourceReference;

/**
 * The resource a delegated administration check is about (D22): one change a
 * management service is to make, named by what it changes, so the decision of
 * its action is the decision of that change.
 *
 * It names the administration action, the record acted on (a role, permission
 * or policy), the grantee (an identity, a principal, a role, or the resource a
 * resource policy is attached to), the intended tenant, whether a grant reaches
 * the tenants below it, the application, the expiry and the proposed change,
 * and whether the change can only narrow what anyone may do (see `Narrowing`).
 * The grantee, the record, the scope and the expiry are also held as values,
 * for the administration stage to weigh (see `OperationConstraints`). A service
 * builds one for each change it makes, and a screen that builds the same one,
 * through the same named constructor, and checks it through the same acting
 * context, gets the same decision.
 *
 * Its reference is a record of type `authorization:operation` whose id is the
 * id of the operation the service runs, which every event of the write shares,
 * so a decision is correlated with the write it allowed (`proposed` for one a
 * screen builds), and whose tenant is the scope of what the change changes,
 * never the tenant the request is in: a change in a tenant is decided in that
 * tenant's scope, and one in a tenant outside the actor's scope, an ancestor's
 * included, is denied as `tenant_scope`, as any resource of that tenant is; a
 * change with no tenant, to a platform-wide grant, a platform role or a
 * platform-owned record, is decided at platform scope, where only a
 * platform-wide grant of the action counts (see `ResourceScope`). A
 * definition's tenant is its owner's. Nothing is ever attached to one
 * operation, so only the policies attached to the operation type are read for
 * it (see `ResourcePolicyResolver`). The reference hands the resource on as its
 * source, so the package's attribute provider (see `OperationAttributes`)
 * offers its attributes to policies under `resource`, and the constraints of
 * the operation (see `OperationConstraints`) read it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class OperationResource implements AuthorizableResource
{
    /** @var string The morph type of every operation resource. */
    public const string TYPE = 'authorization:operation';

    /** @var string The id of an operation resource no service runs, such as one a screen builds. */
    public const string PROPOSED = 'proposed';

    /** @var \SineMacula\Laravel\Authorization\Administration\OperationChange|null The grant or removal the change makes, as values; null for a change to a definition. */
    public ?OperationChange $change;

    /** @var \SineMacula\Laravel\Authorization\Administration\DefinitionChange|null The change to a definition the change makes, as values; null for a grant or a removal. */
    public ?DefinitionChange $definition;

    /**
     * Create a new operation resource.
     *
     * @param  string  $action
     * @param  bool  $isNarrowing
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @param  array<string, mixed>  $attributes
     * @param  \SineMacula\Laravel\Authorization\Administration\DefinitionChange|\SineMacula\Laravel\Authorization\Administration\OperationChange|null  $change
     * @param  string  $id
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $impersonator
     */
    private function __construct(

        /** The administration action the change is decided under. */
        public string $action,

        /** Whether the change can only narrow what anyone may do. */
        public bool $isNarrowing,

        /** The intended tenant, or the owner of a definition; null for the platform. */
        public ?Reference $tenant,

        /** What the change names, as policies read it under `resource`. */
        private array $attributes,

        // The grant or removal the change makes, or the change to a definition,
        // as values.
        DefinitionChange|OperationChange|null $change = null,

        /** The id of the operation that makes the change, or `proposed`. */
        public string $id = self::PROPOSED,

        /** Who is impersonating the actor making the change, or null when no one is. */
        public ?Reference $impersonator = null,
    ) {
        $this->change     = $change instanceof OperationChange ? $change : null;
        $this->definition = $change instanceof DefinitionChange ? $change : null;
    }

    /**
     * Return the operation resource of a grant, an attachment or a boundary
     * set: the target (a role, permission or policy) handed to the grantee in
     * the scope, until the expiry or forever. It may widen what the grantee may
     * do, so it never only narrows, unless it only shortens or narrows a grant
     * the grantee holds live in the scope (see `Narrowing::isShortening()`).
     *
     * @param  string  $action
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  \Illuminate\Database\Eloquent\Model  $target
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $scope
     * @param  \DateTimeInterface|null  $expiresAt
     * @return self
     */
    public static function grant(string $action, Model|Reference $grantee, Model $target, GrantScope $scope, ?\DateTimeInterface $expiresAt = null): self
    {
        $reference  = Reference::of($grantee);
        $change     = new OperationChange($reference, $target, $scope, $expiresAt);
        $attributes = [...self::grantAttributes($reference, $target, $scope), 'expires_at' => $change->expiresAt?->format(\DATE_ATOM)];

        return new self($action, Narrowing::isShortening($action, $change), $scope->tenant, $attributes, $change);
    }

    /**
     * Return the operation resource of a revocation, a detach or a boundary
     * removal: the target taken from the grantee in the scope. Whether it can
     * only narrow is judged from the action and the target (see `Narrowing`).
     *
     * @param  string  $action
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  \Illuminate\Database\Eloquent\Model  $target
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $scope
     * @return self
     */
    public static function revoke(string $action, Model|Reference $grantee, Model $target, GrantScope $scope): self
    {
        $reference = Reference::of($grantee);
        $change    = new OperationChange($reference, $target, $scope);

        return new self($action, Narrowing::isNarrowing($action, $target), $scope->tenant, self::grantAttributes($reference, $target, $scope), $change);
    }

    /**
     * Return the operation resource of a change a call asks for that changes
     * nothing: a target the grantee holds live that a sync keeps, or, with no
     * target, a call that finds nothing to change, such as a removal of what
     * the grantee does not hold. It writes nothing, so it only narrows, and is
     * decided on its action alone, so an actor that may not take the action is
     * refused whether or not the grantee holds anything.
     *
     * @param  string  $action
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  \Illuminate\Database\Eloquent\Model|null  $target
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $scope
     * @return self
     */
    public static function unchanged(string $action, Model|Reference $grantee, ?Model $target, GrantScope $scope): self
    {
        $reference = Reference::of($grantee);
        $change    = new OperationChange($reference, $target, $scope, null, true);

        return new self($action, true, $scope->tenant, [...self::grantAttributes($reference, $target, $scope), 'unchanged' => true], $change);
    }

    /**
     * Return the operation resource of a change to a definition: creating,
     * renaming, updating, re-parenting or deleting a role, permission or
     * policy, with the proposed change, each value a scalar or null, and, for a
     * policy given a new document, that document as it would be stored. It is
     * decided in the tenant that owns the record, as read before the change,
     * and is weighed by what it changes (see `DefinitionConstraints`), so it is
     * never marked as only narrowing.
     *
     * @param  string  $action
     * @param  \Illuminate\Database\Eloquent\Model  $record
     * @param  array<string, bool|float|int|string|null>  $change
     * @param  array<string, mixed>|null  $document
     * @return self
     */
    public static function definition(string $action, Model $record, array $change = [], ?array $document = null): self
    {
        return new self($action, false, Reference::tenantOf($record), [...self::targetAttributes($record), 'change' => $change], new DefinitionChange($record, $change, $document));
    }

    /**
     * Return this operation resource as the operation with the id makes it,
     * while the impersonator, when there is one, impersonates its actor.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $impersonator
     * @param  string|null  $id
     * @return self
     */
    public function actedBy(?Reference $impersonator, ?string $id = null): self
    {
        return new self($this->action, $this->isNarrowing, $this->tenant, $this->attributes, $this->change ?? $this->definition, $id ?? $this->id, $impersonator);
    }

    /**
     * Return the descriptor of the delegation of a permission this change
     * proposes, as the explicit grantable right is decided on (N77): the same
     * operation, named by the same attributes, the grantee and the reach
     * included, under `authorization:permission.grantable`, naming the
     * permission given, such as one a granted role carries, or the change's
     * own. The administration stage never weighs a descriptor, so a screen
     * asking about it gets the decision the stage asks for.
     *
     * @param  \Illuminate\Database\Eloquent\Model|null  $permission
     * @return self
     */
    public function grantable(?Model $permission = null): self
    {
        return $this->descriptor(PackagePermissions::PERMISSION_GRANTABLE, $permission === null ? [] : self::targetAttributes($permission));
    }

    /**
     * Return the descriptor of the delegation of a policy this change proposes,
     * as `authorization:policy.grantable` is decided on (N77): the same
     * operation, naming the policy and the digest of its document (see
     * `DocumentDigest`), so a right a policy allows for one document, by a
     * condition on `resource.digest`, never covers the policy rewritten.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @param  string  $digest
     * @return self
     */
    public function policyGrantable(Policy $policy, string $digest): self
    {
        return $this->descriptor(PackagePermissions::POLICY_GRANTABLE, [...self::targetAttributes($policy), 'digest' => $digest]);
    }

    /**
     * Determine whether this is the descriptor of a delegation a grantable
     * right is decided on, which the administration stage never weighs.
     *
     * @return bool
     */
    public function isDescriptor(): bool
    {
        return \in_array($this->action, [PackagePermissions::PERMISSION_GRANTABLE, PackagePermissions::POLICY_GRANTABLE], true);
    }

    /**
     * Determine whether the change changes nothing, as a call that finds
     * nothing to change, or a sync that keeps a row held live, asks for.
     *
     * @return bool
     */
    public function isUnchanged(): bool
    {
        return $this->change->isUnchanged ?? false;
    }

    /**
     * Return what the change names, nested by key, as the package's attribute
     * provider offers it under `resource`; a key with no value is left out.
     *
     * @return array<string, mixed>
     */
    public function attributes(): array
    {
        $impersonator = $this->impersonator === null ? [] : ['impersonator_type' => $this->impersonator->type, 'impersonator_id' => $this->impersonator->id];

        $attributes = [
            'action'       => $this->action,
            'narrowing'    => $this->isNarrowing,
            'impersonated' => $this->impersonator !== null,
            ...$impersonator,
            ...$this->attributes,
        ];

        return \array_filter($attributes, static fn (mixed $value): bool => $value !== null && $value !== []);
    }

    /**
     * Return the reference to the operation: a record of the operation type,
     * keyed by the operation's id, in the intended tenant, handing this
     * resource on as its source.
     *
     * @return \SineMacula\Laravel\Authorization\Support\ResourceReference
     */
    #[\Override]
    public function toResourceReference(): ResourceReference
    {
        return new ResourceReference(self::TYPE . ':' . $this->id, self::TYPE, $this->id, $this->tenant, null, $this);
    }

    /**
     * Return the descriptor of the delegation under the grantable right, the
     * same operation with the attributes given in place of its own.
     *
     * @param  string  $right
     * @param  array<string, mixed>  $attributes
     * @return self
     */
    private function descriptor(string $right, array $attributes): self
    {
        $named = [...$this->attributes, ...$attributes, 'unchanged' => null];

        return new self($right, false, $this->tenant, $named, $this->change ?? $this->definition, $this->id, $this->impersonator);
    }

    /**
     * Return what a grant or a removal names: the target, when there is one,
     * the grantee, and the scope's application and reach.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $reference
     * @param  \Illuminate\Database\Eloquent\Model|null  $target
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $scope
     * @return array<string, mixed>
     */
    private static function grantAttributes(Reference $reference, ?Model $target, GrantScope $scope): array
    {
        return [
            ...($target === null ? [] : self::targetAttributes($target)),
            'grantee_type' => $reference->type,
            'grantee_id'   => $reference->id,
            'application'  => $scope->application,
            'subtree'      => $scope->includeSubtree,
        ];
    }

    /**
     * Return what names the record acted on: its type and key, when it has one,
     * and its name under its kind, `role`, `permission` or `policy`.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $record
     * @return array<string, mixed>
     */
    private static function targetAttributes(Model $record): array
    {
        $key  = $record->getKey();
        $name = $record->getAttribute('name');
        $kind = match (true) {
            $record instanceof Role       => 'role',
            $record instanceof Permission => 'permission',
            $record instanceof Policy     => 'policy',
            default                       => null,
        };

        return [
            'target_type' => $record->getMorphClass(),
            'target_id'   => \is_scalar($key) && $key !== '' ? (string) $key : null,
            ...($kind === null || !\is_string($name) ? [] : [$kind => $name]),
        ];
    }
}
