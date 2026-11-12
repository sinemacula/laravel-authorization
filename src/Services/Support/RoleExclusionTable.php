<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Services\Support;

use Carbon\CarbonImmutable;
use Illuminate\Database\Connection;
use Illuminate\Database\Query\Builder;
use Illuminate\Support\Carbon;
use SineMacula\Laravel\Authorization\Config\TableNames;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
use SineMacula\Laravel\Authorization\Database\UtcDateTime;
use SineMacula\Laravel\Authorization\Enums\GrantOutcome;
use SineMacula\Laravel\Authorization\Exclusions\RoleExclusion;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * The pairs of mutually exclusive roles, read and written by the role exclusion
 * service inside its transaction (AUTHZ-11.8, N135), on the package's
 * connection, in the table `authorization.tables.role_exclusions` names.
 *
 * A pair is one row, its roles in the pair's canonical order, the lower key
 * first (see `ExclusionPair`). Declaring one inserts its row with
 * insert-or-ignore against the table's primary key, so declaring a pair that is
 * there, including one a concurrent transaction has just declared, never
 * surfaces a unique-constraint violation: the row is read back under a row lock
 * and left alone. Every row the writer inserts records the actor the call names
 * in `granted_by_type` and `granted_by_id`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RoleExclusionTable
{
    /**
     * Create a new writer of the pairs.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  string  $table
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $grantedBy
     */
    public function __construct(

        /** The package connection the table lives on. */
        private Connection $connection,

        /** The role exclusions table. */
        private string $table,

        /** Who declares a pair, recorded on each row written; null for none. */
        private ?Reference $grantedBy = null,
    ) {}

    /**
     * Return the writer of the pairs on the package's connection, recording the
     * actor given on each row it writes.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $grantedBy
     * @return self
     */
    public static function of(?Reference $grantedBy = null): self
    {
        return new self(AuthorizationConnection::connection(), TableNames::get('role_exclusions'), $grantedBy);
    }

    /**
     * Determine whether the pair is declared, read under a row lock.
     *
     * @param  string  $role
     * @param  string  $excluded
     * @return bool
     */
    public function isDeclared(string $role, string $excluded): bool
    {
        return $this->pair($role, $excluded)->lockForUpdate()->exists();
    }

    /**
     * Return the pair as stored, read under a row lock, or null when it is not
     * declared.
     *
     * @param  string  $roleType
     * @param  string  $role
     * @param  string  $excluded
     * @return \SineMacula\Laravel\Authorization\Exclusions\RoleExclusion|null
     */
    public function find(string $roleType, string $role, string $excluded): ?RoleExclusion
    {
        $row = $this->pair($role, $excluded)->lockForUpdate()->first();

        return $row === null ? null : self::exclusionOf((array) $row, $roleType);
    }

    /**
     * Declare the pair, owned by the tenant given or the platform, and report
     * what changed: a new pair, nothing when it was declared already, or null
     * when no row could be written or found.
     *
     * @param  string  $role
     * @param  string  $excluded
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $owner
     * @return \SineMacula\Laravel\Authorization\Enums\GrantOutcome|null
     */
    public function declare(string $role, string $excluded, ?Reference $owner): ?GrantOutcome
    {
        $now = Carbon::now('UTC');

        $inserted = $this->connection->table($this->table)->insertOrIgnore([
            'role_id'          => $role,
            'excluded_role_id' => $excluded,
            'tenant_type'      => $owner?->type,
            'tenant_id'        => $owner?->id,
            'granted_by_type'  => $this->grantedBy?->type,
            'granted_by_id'    => $this->grantedBy?->id,
            'created_at'       => $now,
            'updated_at'       => $now,
        ]);

        if ($inserted === 1) {
            return GrantOutcome::GRANTED;
        }

        // A locking read: on MySQL a plain read would see the transaction's
        // snapshot rather than the row it has just been refused by.
        return $this->isDeclared($role, $excluded) ? GrantOutcome::UNCHANGED : null;
    }

    /**
     * Remove the pair, and report whether it was declared.
     *
     * @param  string  $role
     * @param  string  $excluded
     * @return bool
     */
    public function remove(string $role, string $excluded): bool
    {
        return $this->pair($role, $excluded)->delete() > 0;
    }

    /**
     * Return every pair declared, or every pair naming the role with the key,
     * on the write connection, ordered by their roles' keys.
     *
     * @param  string  $roleType
     * @param  string|null  $role
     * @return list<\SineMacula\Laravel\Authorization\Exclusions\RoleExclusion>
     */
    public function pairs(string $roleType, ?string $role = null): array
    {
        $query = $this->connection->table($this->table)->useWritePdo()->orderBy('role_id')->orderBy('excluded_role_id');

        if ($role !== null) {
            $query->where(static fn (Builder $named): Builder => $named->where('role_id', $role)->orWhere('excluded_role_id', $role));
        }

        $pairs = [];

        foreach ($query->get() as $row) {
            $pairs[] = self::exclusionOf((array) $row, $roleType);
        }

        return $pairs;
    }

    /**
     * Return the pair a row holds, its roles of the type given.
     *
     * @param  array<string, mixed>  $columns
     * @param  string  $roleType
     * @return \SineMacula\Laravel\Authorization\Exclusions\RoleExclusion
     */
    private static function exclusionOf(array $columns, string $roleType): RoleExclusion
    {
        $text = static fn (string $column): ?string => \is_scalar($columns[$column] ?? null) ? (string) $columns[$column] : null;
        $pair = static function (string $type, string $id) use ($text): ?Reference {
            $typed = $text($type);
            $keyed = $text($id);

            return $typed === null || $keyed === null ? null : new Reference($typed, $keyed);
        };

        $createdAt = UtcDateTime::toUtc($columns['created_at'] ?? null);

        return new RoleExclusion(
            new Reference($roleType, (string) $text('role_id')),
            new Reference($roleType, (string) $text('excluded_role_id')),
            $pair('tenant_type', 'tenant_id'),
            $pair('granted_by_type', 'granted_by_id'),
            $createdAt === null ? null : CarbonImmutable::instance($createdAt),
        );
    }

    /**
     * Query the row of the pair.
     *
     * @param  string  $role
     * @param  string  $excluded
     * @return \Illuminate\Database\Query\Builder
     */
    private function pair(string $role, string $excluded): Builder
    {
        return $this->connection->table($this->table)->where('role_id', $role)->where('excluded_role_id', $excluded);
    }
}
