<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Reviews\Support;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Authorization\Database\UtcDateTime;
use SineMacula\Laravel\Authorization\Reviews\OriginScope;
use SineMacula\Laravel\Authorization\Reviews\SupportingGrant;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * One stored row an access review reads, as plain values: a role granted, a
 * permission granted, a policy attached (to a grantee or to a role), or a
 * permission carried by a role, which holds no scope, timestamps or actor of
 * its own.
 *
 * Its key is built from the columns that make it unique in its table: the
 * target, the grantee, the tenant as stored and the application of a grant, and
 * the role and permission of an edge.
 *
 * A row keeps both where it is stored to hold (`origin`, its tenant columns as
 * they are) and where a check reads it (`scope`). The two differ only for a row
 * naming half a tenant, which the package never writes: a check reads a key
 * without a type at the platform, by its missing type alone, so its scope is
 * the platform's; and a type without a key nowhere, so it is not placed (see
 * `isPlaced()`), and meets an attachment, or a grant, only one that holds
 * everywhere (see `canMeet()`).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class GrantRow
{
    /** @var string The source of a role's permission edge, beside the grant targets' own. */
    public const string EDGE = 'role_permission';

    /**
     * Create a new stored row.
     *
     * @param  string  $source
     * @param  string  $targetId
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope|null  $scope
     * @param  array{expires_at: \Carbon\CarbonImmutable|null, created_at: \Carbon\CarbonImmutable|null, updated_at: \Carbon\CarbonImmutable|null}  $times
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $grantedBy
     * @param  \SineMacula\Laravel\Authorization\Reviews\OriginScope|null  $origin
     */
    public function __construct(

        /** The table the row is read from: a grant target's value, or `EDGE`. */
        public string $source,

        /** The key of the role, permission or policy the row grants. */
        public string $targetId,

        /** Whom the row grants to: the grantee, or the role carrying a permission. */
        public Reference $grantee,

        /** Where a check reads the row as holding: its whole tenant, else the platform; null for an edge. */
        public ?GrantScope $scope,

        /** The row's expiry, creation and update, each in UTC or null. */
        public array $times,

        /** The last actor to grant or change the row; null for none. */
        public ?Reference $grantedBy,

        /** Where the row is stored to hold, its tenant columns as they are; null for the scope's own. */
        public ?OriginScope $origin = null,
    ) {}

    /**
     * Return the stored row a query read, its columns named as `GrantRows`
     * selects them, the grantee of an edge being the role of the type given.
     *
     * @param  object  $row
     * @param  string  $source
     * @param  string|null  $roleType
     * @return self
     */
    public static function from(object $row, string $source, ?string $roleType = null): self
    {
        $columns = (array) $row;
        $text    = static fn (string $column): ?string => \is_scalar($columns[$column] ?? null) ? (string) $columns[$column] : null;
        $grantee = new Reference($roleType ?? (string) $text('grantee_type'), (string) $text('grantee_id'));

        $times = [
            'expires_at' => self::instant($columns['expires_at'] ?? null),
            'created_at' => self::instant($columns['created_at'] ?? null),
            'updated_at' => self::instant($columns['updated_at'] ?? null),
        ];

        $origin = $roleType === null ? self::originOf($columns) : null;
        $scope  = $origin   === null ? null : new GrantScope($origin->tenant(), $origin->application, $origin->includeSubtree);

        return new self($source, (string) $text('target_id'), $grantee, $scope, $times, self::pair($text('granted_by_type'), $text('granted_by_id')), $origin);
    }

    /**
     * Return the row's key: its source and the columns that make it unique, the
     * tenant's as stored.
     *
     * @return string
     */
    public function key(): string
    {
        $origin = $this->originScope();

        if ($origin === null) {
            return ReviewOrder::key([$this->source, $this->grantee->id, $this->targetId]);
        }

        return ReviewOrder::key([$this->source, $this->targetId, $this->grantee->type, $this->grantee->id, $origin->tenantType, $origin->tenantId, $origin->application]);
    }

    /**
     * Return where the row is stored to hold, or null for an edge.
     *
     * @return \SineMacula\Laravel\Authorization\Reviews\OriginScope|null
     */
    public function originScope(): ?OriginScope
    {
        return $this->origin ?? ($this->scope === null ? null : OriginScope::of($this->scope));
    }

    /**
     * Determine whether the row names half a tenant: a type without a key, or a
     * key without a type.
     *
     * @return bool
     */
    public function isMalformed(): bool
    {
        return $this->originScope()?->isMalformed() ?? false;
    }

    /**
     * Determine whether a check reads the row anywhere: every row but one
     * naming a tenant type without a key.
     *
     * @return bool
     */
    public function isPlaced(): bool
    {
        $origin = $this->originScope();

        return $origin === null || $origin->tenantType === null || $origin->tenantId !== null;
    }

    /**
     * Determine whether the row and the other can meet as a role's grant and
     * its policy attachment do: a row that is not placed meets only a placed
     * row that holds everywhere, at the platform, never another that is not
     * placed; any other two meet where their scopes do (see
     * `ReviewRun::intersects()`).
     *
     * @param  self  $other
     * @return bool
     */
    public function canMeet(self $other): bool
    {
        return ($this->isPlaced() || $other->isEverywhere()) && ($other->isPlaced() || $this->isEverywhere());
    }

    /**
     * Return the row's expiry, in UTC, or null for never.
     *
     * @return \Carbon\CarbonImmutable|null
     */
    public function expiresAt(): ?CarbonImmutable
    {
        return $this->times['expires_at'];
    }

    /**
     * Determine whether the row still counts at the instant: it has no expiry,
     * or one after the instant.
     *
     * @param  \Carbon\CarbonImmutable  $now
     * @return bool
     */
    public function isLiveAt(CarbonImmutable $now): bool
    {
        $expiresAt = $this->expiresAt();

        return $expiresAt === null || $expiresAt->greaterThan($now);
    }

    /**
     * Return the row as a row a route rests on.
     *
     * @return \SineMacula\Laravel\Authorization\Reviews\SupportingGrant
     */
    public function supporting(): SupportingGrant
    {
        return new SupportingGrant($this->key(), $this->originScope(), $this->expiresAt());
    }

    /**
     * Return the sort key of the row's grantee and scope, in the review's
     * order: the grantee's type and key, then the tenant's type and key as
     * stored, the application and the reach, each nullable one tagged, as the
     * grant queries order them.
     *
     * @return list<bool|int|string|null>
     */
    public function orderKey(): array
    {
        $origin = $this->originScope();

        return [
            $this->grantee->type,
            $this->grantee->id,
            ...ReviewOrder::nullable($origin?->tenantType),
            ...ReviewOrder::nullable($origin?->tenantId),
            ...ReviewOrder::nullable($origin?->application),
            $origin !== null && $origin->includeSubtree,
        ];
    }

    /**
     * Determine whether a check reads the row in every tenant: it is placed,
     * and its scope is the platform's.
     *
     * @return bool
     */
    private function isEverywhere(): bool
    {
        return $this->isPlaced() && $this->scope !== null && $this->scope->tenant === null;
    }

    /**
     * Return where the columns say a grant is stored to hold: its tenant's type
     * and key as they are, its application and its reach.
     *
     * @param  array<array-key, mixed>  $columns
     * @return \SineMacula\Laravel\Authorization\Reviews\OriginScope
     */
    private static function originOf(array $columns): OriginScope
    {
        $type        = $columns['tenant_type']     ?? null;
        $id          = $columns['tenant_id']       ?? null;
        $application = $columns['application']     ?? null;
        $subtree     = $columns['include_subtree'] ?? true;

        return new OriginScope(
            \is_scalar($type) ? (string) $type : null,
            \is_scalar($id) ? (string) $id : null,
            \is_scalar($application) ? (string) $application : null,
            \in_array($subtree, [true, 1, '1', 't', 'true'], true),
        );
    }

    /**
     * Return the reference the two columns name, or null when either is null.
     *
     * @param  string|null  $type
     * @param  string|null  $id
     * @return \SineMacula\Laravel\Authorization\Support\Reference|null
     */
    private static function pair(?string $type, ?string $id): ?Reference
    {
        return $type === null || $id === null ? null : new Reference($type, $id);
    }

    /**
     * Return the stored instant as a UTC instant, or null for none.
     *
     * @param  mixed  $value
     * @return \Carbon\CarbonImmutable|null
     */
    private static function instant(mixed $value): ?CarbonImmutable
    {
        $instant = UtcDateTime::toUtc($value);

        return $instant === null ? null : CarbonImmutable::instance($instant);
    }
}
