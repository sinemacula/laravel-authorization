<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Administration;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableResource;
use SineMacula\Laravel\Authorization\Database\UtcDateTime;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Support\GrantScope;
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
 * A service builds one for each change it makes, and a screen that builds the
 * same one, through the same named constructor, and checks it through the same
 * acting context, gets the same decision.
 *
 * Its reference is a record of type `authorization:operation` whose id is the
 * id of the operation the service runs, which every event of the write shares,
 * so a decision is correlated with the write it allowed (`proposed` for one a
 * screen builds), and whose tenant is the intended tenant: a change in a tenant
 * is decided in that tenant's scope, and one in a tenant outside the actor's
 * scope is denied as `tenant_scope`, as any resource of that tenant is. A
 * definition's tenant is its owner's. The reference hands the resource on as
 * its source, so the package's attribute provider (see `OperationAttributes`)
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

    /**
     * Create a new operation resource.
     *
     * @param  string  $action
     * @param  bool  $isNarrowing
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @param  array<string, mixed>  $attributes
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

        /** The id of the operation that makes the change, or `proposed`. */
        public string $id = self::PROPOSED,

        /** Who is impersonating the actor making the change, or null when no one is. */
        public ?Reference $impersonator = null,
    ) {}

    /**
     * Return the operation resource of a grant, an attachment or a boundary
     * set: the target (a role, permission or policy) handed to the grantee in
     * the scope, until the expiry or forever. It widens what the grantee may
     * do, so it never only narrows.
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
        $expiry = UtcDateTime::toUtc($expiresAt)?->format(\DATE_ATOM);

        return new self($action, false, $scope->tenant, [...self::grantAttributes($grantee, $target, $scope), 'expires_at' => $expiry]);
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
        return new self($action, Narrowing::isNarrowing($action, $target), $scope->tenant, self::grantAttributes($grantee, $target, $scope));
    }

    /**
     * Return the operation resource of a change to a definition: creating,
     * renaming, updating, re-parenting or deleting a role, permission or
     * policy, with the proposed change, each value a scalar or null. It is
     * decided in the tenant that owns the record, and never only narrows.
     *
     * @param  string  $action
     * @param  \Illuminate\Database\Eloquent\Model  $record
     * @param  array<string, bool|float|int|string|null>  $change
     * @return self
     */
    public static function definition(string $action, Model $record, array $change = []): self
    {
        return new self($action, false, Reference::tenantOf($record), [...self::targetAttributes($record), 'change' => $change]);
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
        return new self($this->action, $this->isNarrowing, $this->tenant, $this->attributes, $id ?? $this->id, $impersonator);
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
     * Return what a grant or a removal names: the target, the grantee, and the
     * scope's application and reach.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  \Illuminate\Database\Eloquent\Model  $target
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $scope
     * @return array<string, mixed>
     */
    private static function grantAttributes(Model|Reference $grantee, Model $target, GrantScope $scope): array
    {
        $reference = Reference::of($grantee);

        return [
            ...self::targetAttributes($target),
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
