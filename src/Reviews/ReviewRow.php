<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Reviews;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Authorization\Reviews\Enums\GrantState;
use SineMacula\Laravel\Authorization\Reviews\Enums\SourceKind;
use SineMacula\Laravel\Authorization\Reviews\Enums\SubjectState;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * One row of an access review (N93): one route by which a subject holds a
 * target, or one stored row a review of expiries or of an actor lists.
 *
 * A row names references alone, each a morph type and a string key, never a
 * name, an email, a description, a document or a value. Its shape is versioned
 * (`VERSION`, see `toArray()`):
 *
 * - `row_key`: a key of the row, the same for the same route every time;
 * - `subject`: who holds the target; `grantee`: whom the stored grant names,
 *   the identity for a grant that reaches the subject through it;
 * - `target`: the role, permission or policy held;
 * - `source_kind` and `source_key`: the kind of the stored row the route starts
 *   from (see `Enums\SourceKind`) and its key, built from the columns that make
 *   it unique;
 * - `origin_scope`: where that row holds, as stored (see `OriginScope`): its
 *   tenant's type and key, null for the platform, its application, null for
 *   every application, and whether it reaches the tenants below; null for a
 *   role edge. A row naming half a tenant shows the half it stores, the other
 *   null, and is `malformed`;
 * - `via_identity`: the identity a grant reaches the subject through, else
 *   null;
 * - `role_path`: the roles from the role granted up to the one carrying the
 *   target, through the hierarchy;
 * - `supporting_grants`: every stored row the route rests on, each with its
 *   key, scope and expiry;
 * - `created_at`, `updated_at`, `expires_at`: the starting row's timestamps and
 *   expiry; `route_expires_at`: the earliest expiry of every row the route
 *   rests on, when this route ends, though another route may keep the target
 *   held;
 * - `granted_by`: the last actor to grant or change the starting row (N95),
 *   null for a trusted write or a role edge;
 * - `grant_state`: whether the starting row still counts at the review's
 *   instant, `live` or `expired`, or `malformed` when a row the route rests on
 *   names half a tenant (see `Enums\GrantState`); `subject_state`: what the
 *   review knows of the subject;
 * - `usage`: what the review knows of the route's use, `used`, `unused` or
 *   `unknown`, with its last observed use and the coverage of tracking (see
 *   `RowUsage`); `unknown` while grant usage tracking is off.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ReviewRow
{
    /** @var int The version of the row's shape. */
    public const int VERSION = 1;

    /**
     * Create a new review row.
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @formatter:off
     *
     * @param  string  $rowKey
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $subject
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $target
     * @param  \SineMacula\Laravel\Authorization\Reviews\Enums\SourceKind  $sourceKind
     * @param  string  $sourceKey
     * @param  \SineMacula\Laravel\Authorization\Reviews\OriginScope|null  $originScope
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $viaIdentity
     * @param  list<\SineMacula\Laravel\Authorization\Support\Reference>  $rolePath
     * @param  list<\SineMacula\Laravel\Authorization\Reviews\SupportingGrant>  $supportingGrants
     * @param  array{created_at: \Carbon\CarbonImmutable|null, updated_at: \Carbon\CarbonImmutable|null, expires_at: \Carbon\CarbonImmutable|null, route_expires_at: \Carbon\CarbonImmutable|null}  $times
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $grantedBy
     * @param  \SineMacula\Laravel\Authorization\Reviews\Enums\GrantState  $grantState
     * @param  \SineMacula\Laravel\Authorization\Reviews\Enums\SubjectState  $subjectState
     * @param  \SineMacula\Laravel\Authorization\Reviews\RowUsage|null  $usage
     *
     * @formatter:on
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     */
    public function __construct(

        /** The key of the row, the same for the same route every time. */
        public string $rowKey,

        /** Who holds the target. */
        public Reference $subject,

        /** Whom the stored grant the route starts from names. */
        public Reference $grantee,

        /** The role, permission or policy held. */
        public Reference $target,

        /** The kind of the stored row the route starts from. */
        public SourceKind $sourceKind,

        /** The key of the stored row the route starts from. */
        public string $sourceKey,

        /** Where the stored row the route starts from holds, as stored; null for a role edge. */
        public ?OriginScope $originScope,

        /** The identity a grant reaches the subject through; null for none. */
        public ?Reference $viaIdentity,

        /** The roles from the role granted up to the one carrying the target. */
        public array $rolePath,

        /** Every stored row the route rests on. */
        public array $supportingGrants,

        /** The starting row's creation, update and expiry, and the route's expiry, each in UTC or null. */
        public array $times,

        /** The last actor to grant or change the starting row; null for none. */
        public ?Reference $grantedBy,

        /** Whether the starting row still counts at the review's instant, or a row the route rests on names half a tenant. */
        public GrantState $grantState,

        /** What the review knows of the subject. */
        public SubjectState $subjectState = SubjectState::UNKNOWN,

        /** What the review knows of the route's use; null when it was not read, which reads as unknown. */
        public ?RowUsage $usage = null,
    ) {}

    /**
     * Return the row with what the review knows of its subject.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\Enums\SubjectState  $state
     * @return self
     */
    public function withSubjectState(SubjectState $state): self
    {
        return new self(
            $this->rowKey,
            $this->subject,
            $this->grantee,
            $this->target,
            $this->sourceKind,
            $this->sourceKey,
            $this->originScope,
            $this->viaIdentity,
            $this->rolePath,
            $this->supportingGrants,
            $this->times,
            $this->grantedBy,
            $this->grantState,
            $state,
            $this->usage,
        );
    }

    /**
     * Return the row with what the review knows of its use.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\RowUsage  $usage
     * @return self
     */
    public function withUsage(RowUsage $usage): self
    {
        return new self(
            $this->rowKey,
            $this->subject,
            $this->grantee,
            $this->target,
            $this->sourceKind,
            $this->sourceKey,
            $this->originScope,
            $this->viaIdentity,
            $this->rolePath,
            $this->supportingGrants,
            $this->times,
            $this->grantedBy,
            $this->grantState,
            $this->subjectState,
            $usage,
        );
    }

    /**
     * Return when the row's starting grant was created, or null when it records
     * none.
     *
     * @return \Carbon\CarbonImmutable|null
     */
    public function createdAt(): ?CarbonImmutable
    {
        return $this->times['created_at'];
    }

    /**
     * Return when the route ends: the earliest expiry among the rows it rests
     * on, or null when none expires.
     *
     * @return \Carbon\CarbonImmutable|null
     */
    public function routeExpiresAt(): ?CarbonImmutable
    {
        return $this->times['route_expires_at'];
    }

    /**
     * Return the row in its versioned shape, as plain values.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'version'           => self::VERSION,
            'row_key'           => $this->rowKey,
            'subject'           => self::referenceArray($this->subject),
            'grantee'           => self::referenceArray($this->grantee),
            'target'            => self::referenceArray($this->target),
            'source_kind'       => $this->sourceKind->value,
            'source_key'        => $this->sourceKey,
            'origin_scope'      => $this->originScope?->toArray(),
            'via_identity'      => self::referenceArray($this->viaIdentity),
            'role_path'         => \array_map(static fn (Reference $role): array => ['type' => $role->type, 'id' => $role->id], $this->rolePath),
            'supporting_grants' => \array_map(static fn (SupportingGrant $grant): array => $grant->toArray(), $this->supportingGrants),
            'created_at'        => self::instant($this->times['created_at']),
            'updated_at'        => self::instant($this->times['updated_at']),
            'expires_at'        => self::instant($this->times['expires_at']),
            'route_expires_at'  => self::instant($this->times['route_expires_at']),
            'granted_by'        => self::referenceArray($this->grantedBy),
            'grant_state'       => $this->grantState->value,
            'subject_state'     => $this->subjectState->value,
            'usage'             => ($this->usage ?? RowUsage::unknown())->toArray(),
        ];
    }

    /**
     * Return an instant as an ISO 8601 string in UTC, or null for none.
     *
     * @param  \Carbon\CarbonImmutable|null  $instant
     * @return string|null
     *
     * @internal
     */
    public static function instant(?CarbonImmutable $instant): ?string
    {
        return $instant?->utc()->format('Y-m-d\TH:i:s\Z');
    }

    /**
     * Return a reference as its type and key, or null for none.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $reference
     * @return array{type: string, id: string}|null
     */
    private static function referenceArray(?Reference $reference): ?array
    {
        return $reference === null ? null : ['type' => $reference->type, 'id' => $reference->id];
    }
}
