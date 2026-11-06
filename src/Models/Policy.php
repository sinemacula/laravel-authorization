<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Models;

use Illuminate\Container\Container;
use Illuminate\Database\Eloquent\Attributes\ObservedBy;
use Illuminate\Database\Eloquent\Casts\Attribute;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphTo;
use SineMacula\Laravel\Authorization\Concerns\HasSystemProtection;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
use SineMacula\Laravel\Authorization\Evaluation\PolicyValidator;
use SineMacula\Laravel\Authorization\Exceptions\SystemPolicyProtectedException;
use SineMacula\Laravel\Authorization\Observers\PolicyObserver;
use SineMacula\Laravel\Authorization\Support\PolicyDocument;

/**
 * Eloquent model for policy rows.
 *
 * The `document` column persists the full statement body as JSON. A write is
 * refused, with an invalid policy document exception, unless the policy
 * validator accepts the document: a valid policy, within the limits, naming
 * only actions the code declares. The `is_system` flag marks platform-shipped
 * policies as protected: deleting, editing or clearing the flag of a persisted
 * `is_system = true` row raises `SystemPolicyProtectedException` unless
 * `forceSystem()` is invoked to unlock the next operation on the instance. A
 * policy is owned by the platform (both tenant columns null) or by one tenant
 * (both set), and its name is unique within its owner.
 *
 * A managed policy (both owner columns null) is attached to any number of
 * grantees and roles. An inline policy names, in `owner_type` and `owner_id`,
 * the one grantee it belongs to: it is attached to that grantee alone, its name
 * is unique among that grantee's inline policies, and it is deleted with the
 * grantee (see `InlinePolicies`).
 *
 * @property string $id
 * @property string $name
 * @property string|null $description
 * @property array<string, mixed> $document
 * @property bool $is_system
 * @property string|null $tenant_type
 * @property string|null $tenant_id
 * @property string|null $owner_type
 * @property string|null $owner_id
 *
 * @inheritable
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
#[ObservedBy(PolicyObserver::class)]
class Policy extends Model
{
    use HasSystemProtection, HasUuids;

    /** @var list<string> Attributes that are mass assignable. */
    protected $fillable = [
        'name',
        'description',
        'document',
        'is_system',
        'tenant_type',
        'tenant_id',
        'owner_type',
        'owner_id',
    ];

    /**
     * Create a new Eloquent model instance.
     *
     * Binds the model to the table the package configuration names. The table
     * has to be set on each instantiation so runtime config swaps take effect,
     * so this is construction rather than model behaviour.
     *
     * @param  array<string, mixed>  $attributes
     *
     * @phpstan-ignore sineMaculaLaravel.modelBehaviour
     */
    public function __construct(array $attributes = [])
    {
        parent::__construct($attributes);

        /** @var string $table */
        $table       = config('authorization.tables.policies', 'policies');
        $this->table = $table;
    }

    /**
     * Return the connection the policy table lives on: the configured
     * `authorization.connection`, else the instance's own, else the
     * application's default.
     *
     * Naming the connection is schema, so this is a framework hook rather than
     * model behaviour.
     *
     * @return string
     *
     * @phpstan-ignore sineMaculaLaravel.modelBehaviour
     */
    #[\Override]
    public function getConnectionName(): string
    {
        return AuthorizationConnection::resolve(parent::getConnectionName());
    }

    /**
     * The tenant that owns this policy.
     *
     * A null morph pair marks the policy as platform-wide.
     *
     * @return \Illuminate\Database\Eloquent\Relations\MorphTo<\Illuminate\Database\Eloquent\Model, $this>
     */
    public function tenant(): MorphTo
    {
        return $this->morphTo('tenant');
    }

    /**
     * The grantee an inline policy belongs to.
     *
     * A null morph pair marks a managed policy, which belongs to no grantee.
     *
     * @return \Illuminate\Database\Eloquent\Relations\MorphTo<\Illuminate\Database\Eloquent\Model, $this>
     */
    public function owner(): MorphTo
    {
        return $this->morphTo('owner');
    }

    /**
     * The attribute cast map.
     *
     * @return array<string, string>
     */
    #[\Override]
    protected function casts(): array
    {
        return [
            'name'        => 'string',
            'description' => 'string',
            'document'    => 'array',
            'is_system'   => 'boolean',
            'tenant_type' => 'string',
            'tenant_id'   => 'string',
            'owner_type'  => 'string',
            'owner_id'    => 'string',
        ];
    }

    /**
     * Interact with the document attribute, refusing a write the policy
     * validator does not accept: an invalid policy, one over the limits, or one
     * naming actions the code does not declare.
     *
     * @return \Illuminate\Database\Eloquent\Casts\Attribute<array<string, mixed>, mixed>
     *
     * @throws \SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException
     */
    protected function document(): Attribute
    {
        return Attribute::make(
            set: function (mixed $value): string {

                $name     = PolicyDocument::nameOf($this->getAttribute('name'));
                $document = PolicyDocument::named(PolicyDocument::decode($value, $name), $this->getAttribute('name'));

                Container::getInstance()->make(PolicyValidator::class)->assertValid($document, $name);

                // The validator refuses a document that cannot be encoded as
                // JSON, so this does not throw; were it ever to, the write
                // would fail rather than store an empty document.
                return \json_encode($document, \JSON_THROW_ON_ERROR);
            },
        );
    }

    /**
     * Construct the per-model exception raised when a protected mutation on a
     * system policy is refused.
     *
     * @param  string  $operation
     * @return \Throwable
     */
    #[\Override]
    protected function systemProtectionException(string $operation): \Throwable
    {
        return new SystemPolicyProtectedException(policyName: $this->systemProtectedName(), operation: $operation);
    }
}
