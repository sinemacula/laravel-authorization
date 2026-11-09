<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Reviews\Support;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Authorization\Database\UtcDateTime;
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
 * target, the grantee, the tenant and the application of a grant, and the role
 * and permission of an edge.
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
     */
    public function __construct(

        /** The table the row is read from: a grant target's value, or `EDGE`. */
        public string $source,

        /** The key of the role, permission or policy the row grants. */
        public string $targetId,

        /** Whom the row grants to: the grantee, or the role carrying a permission. */
        public Reference $grantee,

        /** Where the row holds; null for an edge. */
        public ?GrantScope $scope,

        /** The row's expiry, creation and update, each in UTC or null. */
        public array $times,

        /** The last actor to grant or change the row; null for none. */
        public ?Reference $grantedBy,
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

        $scope = $roleType === null ? self::scopeOf($columns) : null;

        return new self($source, (string) $text('target_id'), $grantee, $scope, $times, self::pair($text('granted_by_type'), $text('granted_by_id')));
    }

    /**
     * Return the row's key: its source and the columns that make it unique.
     *
     * @return string
     */
    public function key(): string
    {
        if ($this->scope === null) {
            return ReviewOrder::key([$this->source, $this->grantee->id, $this->targetId]);
        }

        $tenant = $this->scope->tenant;

        return ReviewOrder::key([$this->source, $this->targetId, $this->grantee->type, $this->grantee->id, $tenant?->type, $tenant?->id, $this->scope->application]);
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
        return new SupportingGrant($this->key(), $this->scope, $this->expiresAt());
    }

    /**
     * Return the sort key of the row's grantee and scope, in the review's
     * order: the grantee's type and key, then the tenant's, the application and
     * the reach, each nullable one tagged.
     *
     * @return list<bool|int|string|null>
     */
    public function orderKey(): array
    {
        return [
            $this->grantee->type,
            $this->grantee->id,
            ...ReviewOrder::nullable($this->scope?->tenant?->type),
            ...ReviewOrder::nullable($this->scope?->tenant?->id),
            ...ReviewOrder::nullable($this->scope?->application),
            $this->scope !== null && $this->scope->includeSubtree,
        ];
    }

    /**
     * Return where the columns say a grant holds: its tenant when both tenant
     * columns are set, else the platform, its application and its reach.
     *
     * @param  array<array-key, mixed>  $columns
     * @return \SineMacula\Laravel\Authorization\Support\GrantScope
     */
    private static function scopeOf(array $columns): GrantScope
    {
        $type        = $columns['tenant_type']     ?? null;
        $id          = $columns['tenant_id']       ?? null;
        $application = $columns['application']     ?? null;
        $subtree     = $columns['include_subtree'] ?? true;

        return new GrantScope(
            self::pair(\is_scalar($type) ? (string) $type : null, \is_scalar($id) ? (string) $id : null),
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
