<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Database;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Query\Builder;
use Illuminate\Support\Carbon;
use SineMacula\Laravel\Authorization\Concerns\HasContainerInstance;
use SineMacula\Laravel\Authorization\Config\BreakGlassConfigValidator;
use SineMacula\Laravel\Authorization\Config\TableNames;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableMachine;

/**
 * Reads break-glass activations (AUTHZ-11.7, N133) as the role grants they
 * stand for, so an activation reaches a check through the path a role grant
 * takes.
 *
 * A grantee's `roles()` relation reads its role grants and its live activations
 * as one set of grant rows (see `roleGrants()`): an activation gives the grant
 * row's columns from its own, its activation for its creation, and its key
 * under `ACTIVATION`, null on a role grant's row, which the relation reads onto
 * each role's pivot. Every check, bulk check, listing, query scope and
 * explanation that reads the grantee's roles through the relation and the
 * resolution cache therefore reads an activation's role, its ancestry,
 * permissions and policies, in the tenant chain and application the relation
 * applies, with the reach of `include_subtree`, and a resolution lives no
 * longer than the nearest activation's expiry, as for a role grant's. A normal
 * grant of the same role is a row of its own, untouched.
 *
 * An activation is live while it has not ended and its expiry is to come. It
 * reaches only a human principal: an activation naming a machine (see
 * `AuthorizableMachine`), or a model read as another subject's separate
 * identity (see `markIdentity()`), counts for nothing, and one naming half a
 * tenant applies nowhere, as a grant row naming one does not (see
 * `TenantChain::grants()`). The note an activation carries is never read here.
 *
 * While `break_glass.enabled` is false no activation counts anywhere (N139):
 * not through the roles relation, nor where delegated administration or the
 * query scopes read the table, and the rows stay for audit. Whether it is on is
 * read once a request or job, when the container builds the record (see
 * `isEnabled()`), never once a check, so the resolution cache, built with it,
 * keeps the entries of either state apart.
 *
 * Whether a model stands as an identity is marked on the instance, for the
 * request or job (the service provider binds the record with `scoped()`), so
 * its resolutions are kept apart from its resolutions as a subject (see
 * `kindOf()`), and an instance once read as an identity counts no activation
 * for the rest of the request or job.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class BreakGlassActivations
{
    use HasContainerInstance;

    /** @var string The column a grant row gives its activation's key under, null for a role grant. */
    public const string ACTIVATION = 'break_glass_id';

    /** @var string The prefix of the kind a resolution of an instance read as an identity is kept under. */
    public const string IDENTITY_KIND = 'identity-';

    /** @var list<string> The columns of a role grant an activation gives from its own columns of the same names. */
    private const array COLUMNS = [
        'role_id',
        'authorizable_type',
        'authorizable_id',
        'tenant_type',
        'tenant_id',
        'include_subtree',
        'application',
        'expires_at',
        'granted_by_type',
        'granted_by_id',
    ];

    /** @var bool Whether break-glass is enabled for the request or job. */
    public readonly bool $isEnabled;

    /** @var \WeakMap<object, true> The instances read as a subject's separate identity in the request or job. */
    private \WeakMap $identities;

    /**
     * Create the record of a request or job, which the container holds for its
     * length (see `scoped()`): whether break-glass is enabled, read through the
     * checks the boot runs, and the instances read as an identity.
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public function __construct()
    {
        $this->isEnabled  = BreakGlassConfigValidator::read()['enabled'];
        $this->identities = new \WeakMap;
    }

    /**
     * Determine whether break-glass is enabled for the request or job; never
     * without the package's record of it.
     *
     * @return bool
     */
    public static function isEnabled(): bool
    {
        return self::instance()->isEnabled ?? false;
    }

    /**
     * Return the query of the role grant rows read in place of the role grant
     * table: every role grant, with no activation, and every live activation,
     * as a role grant row with its key, none when the activations are not
     * counted (see `isCounted()`). The reader narrows the rows to the grantees,
     * the scope and the application it reads.
     *
     * @param  bool  $isCounted
     * @param  \Illuminate\Support\Carbon|null  $now
     * @return \Illuminate\Database\Query\Builder
     */
    public static function roleGrants(bool $isCounted = true, ?Carbon $now = null): Builder
    {
        $connection  = AuthorizationConnection::connection();
        $table       = TableNames::get('break_glass');
        $activation  = $connection->getQueryGrammar()->wrap(self::ACTIVATION);
        $activations = self::live($connection->table($table), $table, $now)
            ->select([...self::COLUMNS, 'activated_at as created_at', 'activated_at as updated_at', 'id as ' . self::ACTIVATION]);

        if (!$isCounted) {
            $activations->whereRaw('1 = 0');
        }

        return $connection->table(TableNames::get('authorizable_roles'))
            ->select([...self::COLUMNS, 'created_at', 'updated_at'])
            ->addSelect(new ComposedExpression("null as {$activation}"))
            ->unionAll($activations);
    }

    /**
     * Limit the query to the activations of the table that are live at the
     * instant given, else now: not ended, and expiring after it; to none while
     * break-glass is disabled.
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @param  string  $table
     * @param  \Illuminate\Support\Carbon|null  $now
     * @return \Illuminate\Database\Query\Builder
     */
    public static function live(Builder $query, string $table, ?Carbon $now = null): Builder
    {
        if (!self::isEnabled()) {
            $query->whereRaw('1 = 0');
        }

        return self::unexpired($query, $table, $now);
    }

    /**
     * Limit the query to the activations of the table not ended and expiring
     * after the instant given, else now, whether break-glass is enabled or not.
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @param  string  $table
     * @param  \Illuminate\Support\Carbon|null  $now
     * @return \Illuminate\Database\Query\Builder
     */
    public static function unexpired(Builder $query, string $table, ?Carbon $now = null): Builder
    {
        return $query->whereNull($table . '.ended_at')->where($table . '.expires_at', '>', $now ?? Carbon::now('UTC'));
    }

    /**
     * Determine whether the grantee's activations count: never while
     * break-glass is disabled, nor a machine's, nor those of an instance read
     * as another subject's identity.
     *
     * @param  object  $grantee
     * @return bool
     */
    public static function isCounted(object $grantee): bool
    {
        return self::isEnabled() && !$grantee instanceof AuthorizableMachine && !self::isIdentity($grantee);
    }

    /**
     * Mark the instance as read as a subject's separate identity, so none of
     * its activations reaches the subject, or the instance, from now on.
     *
     * @param  object  $identity
     * @return void
     */
    public static function markIdentity(object $identity): void
    {
        $marks = self::instance();

        if ($marks === null) {
            return;
        }

        $marks->identities[$identity] = true;
    }

    /**
     * Determine whether the instance was read as a subject's separate identity.
     *
     * @param  object  $grantee
     * @return bool
     */
    public static function isIdentity(object $grantee): bool
    {
        $marks = self::instance();

        return $marks !== null && isset($marks->identities[$grantee]);
    }

    /**
     * Return the kind a resolution of the grantee is kept under: the kind given
     * for a grantee whose activations count as they would, prefixed for an
     * instance read as an identity, whose resolutions count none.
     *
     * @param  string  $kind
     * @param  object  $grantee
     * @return string
     */
    public function kindOf(string $kind, object $grantee): string
    {
        return isset($this->identities[$grantee]) ? self::IDENTITY_KIND . $kind : $kind;
    }

    /**
     * Return the key of the activation a role held was read through, or null
     * for a role read through a role grant, or read otherwise.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $role
     * @return string|null
     */
    public static function activationOf(Model $role): ?string
    {
        $pivot      = $role->relationLoaded('pivot') ? $role->getRelation('pivot') : null;
        $activation = $pivot instanceof Model ? $pivot->getAttribute(self::ACTIVATION) : null;

        return \is_scalar($activation) && $activation !== '' ? (string) $activation : null;
    }
}
