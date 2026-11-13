<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Models;

use Illuminate\Database\Eloquent\Attributes\ObservedBy;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Config\TableNames;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
use SineMacula\Laravel\Authorization\Database\UtcDateTime;
use SineMacula\Laravel\Authorization\Observers\BreakGlassActivationObserver;

/**
 * Eloquent model for a break-glass activation (AUTHZ-11.7, N133): one
 * activation of an emergency role for one principal, for a limited time, its
 * own record beside any normal grant of the same role.
 *
 * `Services\BreakGlassService` creates and ends activations, and break-glass
 * stays disabled until its audit trail ships. A live activation, one not ended
 * whose expiry is still to come, grants its role in its scope through the
 * grantee's `roles()` relation while break-glass is enabled (see
 * `Database\BreakGlassActivations`), and every change made through this model
 * bumps the versions a grant to its grantee bumps (see
 * `BreakGlassActivationObserver`), so the next check sees it.
 *
 * The note is personal data: it is hidden from the model's array and JSON
 * forms, and never cached, logged or put on an event. Every instant is kept in
 * UTC.
 *
 * @property string $id
 * @property string $role_id
 * @property string $authorizable_type
 * @property string $authorizable_id
 * @property string|null $granted_by_type
 * @property string|null $granted_by_id
 * @property string|null $tenant_type
 * @property string|null $tenant_id
 * @property bool $include_subtree
 * @property string|null $application
 * @property string $justification
 * @property string|null $note
 * @property \Illuminate\Support\Carbon $activated_at
 * @property \Illuminate\Support\Carbon $expires_at
 * @property \Illuminate\Support\Carbon|null $ended_at
 * @property string|null $ended_by_type
 * @property string|null $ended_by_id
 * @property string|null $end_reason
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
#[ObservedBy(BreakGlassActivationObserver::class)]
final class BreakGlassActivation extends Model
{
    use HasUuids;

    /** @var bool Whether the model keeps `created_at` and `updated_at`: an activation keeps `activated_at` instead. */
    public $timestamps = false;

    /** @var list<string> Attributes that are mass assignable. */
    protected $fillable = [
        'role_id',
        'authorizable_type',
        'authorizable_id',
        'granted_by_type',
        'granted_by_id',
        'tenant_type',
        'tenant_id',
        'include_subtree',
        'application',
        'justification',
        'note',
        'activated_at',
        'expires_at',
        'ended_at',
        'ended_by_type',
        'ended_by_id',
        'end_reason',
    ];

    /** @var list<string> Attributes never shown in the model's array or JSON form: the note is personal data. */
    protected $hidden = ['note'];

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

        $this->table = TableNames::get('break_glass');
    }

    /**
     * Return the connection the activations table lives on: the configured
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
     * The attribute cast map: every reference and code a string, the reach a
     * boolean, and every instant in UTC.
     *
     * @return array<string, string>
     */
    #[\Override]
    protected function casts(): array
    {
        return [
            'role_id'           => 'string',
            'authorizable_type' => 'string',
            'authorizable_id'   => 'string',
            'granted_by_type'   => 'string',
            'granted_by_id'     => 'string',
            'tenant_type'       => 'string',
            'tenant_id'         => 'string',
            'include_subtree'   => 'boolean',
            'application'       => 'string',
            'justification'     => 'string',
            'note'              => 'string',
            'activated_at'      => UtcDateTime::class,
            'expires_at'        => UtcDateTime::class,
            'ended_at'          => UtcDateTime::class,
            'ended_by_type'     => 'string',
            'ended_by_id'       => 'string',
            'end_reason'        => 'string',
        ];
    }
}
