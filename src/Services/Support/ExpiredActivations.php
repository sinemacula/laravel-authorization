<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Services\Support;

use Carbon\CarbonImmutable;
use Illuminate\Database\Query\Builder;
use Illuminate\Support\Carbon;
use SineMacula\Laravel\Authorization\Config\TableNames;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
use SineMacula\Laravel\Authorization\Enums\GrantTarget;
use SineMacula\Laravel\Authorization\Events\Identity\BreakGlassExpired;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\OperationScope;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\TenantColumns;

/**
 * Records the expiry of every break-glass activation that expired without
 * ending, for `authorization:prune`, whether break-glass is enabled or not:
 * `ended_at` becomes its expiry and `end_reason` `expired`, with no one as
 * `ended_by`, and the row is kept for audit. Each is reported with
 * `BreakGlassExpired`, a chunk at a time, each chunk one operation with no
 * actor, as the sweep is system work.
 *
 * It writes through a query, not the model, and each event's dispatch bumps the
 * grantee's versions as any grant event's does. Only a row still unended is
 * written, so one a surrender or revocation ended meanwhile is neither
 * overwritten nor reported. A row naming half a tenant, which the package never
 * writes, is recorded and counted, but reported by no event, which would name
 * it the platform's or a tenant's.
 *
 * @phpstan-type ActivationRow array{
 *     id: string,
 *     role_id: string,
 *     authorizable_type: string,
 *     authorizable_id: string,
 *     tenant_type: string|null,
 *     tenant_id: string|null,
 *     include_subtree: bool|int|string,
 *     application: string|null,
 *     expires_at: string,
 * }
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ExpiredActivations
{
    /** @var list<string> The columns each activation is read with. */
    private const array COLUMNS = ['id', 'role_id', 'authorizable_type', 'authorizable_id', 'tenant_type', 'tenant_id', 'include_subtree', 'application', 'expires_at'];

    /**
     * Record the expiry of every activation that expired without ending, or,
     * pretending, only count them, and return how many there are.
     *
     * @param  int  $chunk
     * @param  bool  $pretend
     * @return int
     *
     * @throws \Throwable
     */
    public static function record(int $chunk, bool $pretend): int
    {
        if ($pretend) {
            return self::expired()->count();
        }

        return (new ExpiredSweep(self::recordChunk(...)))->run(self::expired(), self::COLUMNS, $chunk);
    }

    /**
     * Record the expiry of one chunk of activations, reporting each, and return
     * how many were recorded.
     *
     * @param  list<ActivationRow>  $rows
     * @param  \SineMacula\Laravel\Authorization\Support\Operation  $operation
     * @return int
     */
    private static function recordChunk(array $rows, Operation $operation): int
    {
        $roles    = [];
        $events   = [];
        $recorded = 0;

        /** @var list<\SineMacula\Laravel\Authorization\Models\Role> $found */
        $found = GrantTarget::ROLE->find(\array_column($rows, 'role_id'));

        foreach ($found as $role) {
            $roles[$role->id] = $role;
        }

        foreach ($rows as $row) {
            $ended = ['ended_at' => $row['expires_at'], 'ended_by_type' => null, 'ended_by_id' => null, 'end_reason' => 'expired'];

            if (self::expired()->where('id', $row['id'])->update($ended) === 0) {
                continue;
            }

            $recorded++;

            if (TenantColumns::isHalf($row['tenant_type'], $row['tenant_id'])) {
                continue;
            }

            // Deleting a role deletes its activations, so a row just recorded
            // has one.
            $role     = $roles[$row['role_id']];
            $tenant   = isset($row['tenant_type'], $row['tenant_id']) ? new Reference($row['tenant_type'], $row['tenant_id']) : null;
            $events[] = new BreakGlassExpired(
                $operation,
                new Reference($row['authorizable_type'], $row['authorizable_id']),
                Reference::of($role),
                $role->name,
                new GrantScope($tenant, $row['application'], (bool) $row['include_subtree']),
                $row['id'],
                CarbonImmutable::parse($row['expires_at'], 'UTC'),
            );
        }

        OperationScope::dispatch(...$events);

        return $recorded;
    }

    /**
     * Query the activations that expired without ending.
     *
     * @return \Illuminate\Database\Query\Builder
     */
    private static function expired(): Builder
    {
        return AuthorizationConnection::connection()->table(TableNames::get('break_glass'))->whereNull('ended_at')->where('expires_at', '<=', Carbon::now('UTC'));
    }
}
