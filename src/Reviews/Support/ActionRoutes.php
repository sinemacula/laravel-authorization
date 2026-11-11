<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Reviews\Support;

use SineMacula\Laravel\Authorization\Config\ModelClasses;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
use SineMacula\Laravel\Authorization\Enums\GrantTarget;
use SineMacula\Laravel\Authorization\Evaluation\Enums\PolicyEffect;
use SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException;
use SineMacula\Laravel\Authorization\Evaluation\Policy;
use SineMacula\Laravel\Authorization\Reviews\ActionEvidence;
use SineMacula\Laravel\Authorization\Reviews\Enums\EvidenceKind;
use SineMacula\Laravel\Authorization\Reviews\Enums\SourceKind;
use SineMacula\Laravel\Authorization\Reviews\OriginScope;
use SineMacula\Laravel\Authorization\Reviews\ReviewRow;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\HeldPermissions;
use SineMacula\Laravel\Authorization\Support\PolicyDocument;

/**
 * The routes of a subject's holdings that give one action (see
 * `ReviewQuery::forAction()`), kept from the routes collected before they are
 * sorted and cut to a page, so a page holds its limit of matching rows in the
 * review's order, each with what gives the action (see `ActionEvidence`).
 *
 * - A permission route, granted directly or carried by a role of the chain,
 *   gives the action when the permission's name covers it under the held
 *   permission rules (see `HeldPermissions`): case-sensitive, a held `*`
 *   pattern covering, the asked action always literal, never matched in SQL.
 * - A policy route, attached directly or to a role of the chain, gives it when
 *   a statement names it (see `ActionStatements`), its effect reported; a
 *   policy that only denies it is kept as deny evidence. A policy whose stored
 *   document cannot be read, invalid or over the limits, is kept as unreadable
 *   evidence, never dropped.
 * - A role route gives nothing by itself: only what a role carries does.
 *
 * Each row's reach is its origin scope, kept compact; for a policy through a
 * role, where the role's grant and the attachment hold together (see
 * `ReviewRun::overlap()`), unless either names half a tenant, whose stored
 * tenant columns are shown as they are, in the application either row names,
 * and whose route is `malformed`.
 *
 * The definitions are read on the write connection, as every review read is, in
 * a fixed number of queries for the routes collected, a chunk of their keys at
 * a time (see `GrantRows::CHUNK`), never one for each route.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ActionRoutes
{
    /**
     * Create the routes giving the action, given the definitions they read.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\Support\ReviewRun  $run
     * @param  string  $action
     * @param  array<array-key, array{name: string, guard: string|null}>  $permissions
     * @param  array<array-key, \SineMacula\Laravel\Authorization\Evaluation\Policy|null>  $policies
     */
    private function __construct(

        /** The run the routes were collected in. */
        private ReviewRun $run,

        /** The action asked about. */
        private string $action,

        /** The name and guard of each permission a route holds, by its key. */
        private array $permissions,

        /** Each policy a route holds, by its key, or null when its document cannot be read. */
        private array $policies,
    ) {}

    /**
     * Keep only the routes collected that give the action, each with what gives
     * it.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\Support\ReviewRun  $run
     * @param  string  $action
     * @param  \SineMacula\Laravel\Authorization\Reviews\Support\RowCollector  $rows
     * @return void
     */
    public static function narrow(ReviewRun $run, string $action, RowCollector $rows): void
    {
        $rows->narrow(static fn (array $read): array => self::reading($run, $action, $read)->kept($read));
    }

    /**
     * Return the routes giving the action, the definitions of the rows' targets
     * read.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\Support\ReviewRun  $run
     * @param  string  $action
     * @param  list<\SineMacula\Laravel\Authorization\Reviews\ReviewRow>  $rows
     * @return self
     */
    private static function reading(ReviewRun $run, string $action, array $rows): self
    {
        $keys = [GrantTarget::PERMISSION->value => [], GrantTarget::POLICY->value => []];

        foreach ($rows as $row) {
            $kind = self::kindOf($row->sourceKind);

            if ($kind === null || !Definitions::isKey($row->target->id)) {
                continue;
            }

            $keys[$kind->value][$row->target->id] = $row->target->id;
        }

        return new self($run, $action, self::permissions($keys[GrantTarget::PERMISSION->value]), self::policies($keys[GrantTarget::POLICY->value]));
    }

    /**
     * Return the rows giving the action, each by its index among the rows and
     * with what gives it.
     *
     * @param  list<\SineMacula\Laravel\Authorization\Reviews\ReviewRow>  $rows
     * @return array<int, \SineMacula\Laravel\Authorization\Reviews\ReviewRow>
     */
    private function kept(array $rows): array
    {
        $kept = [];

        foreach ($rows as $index => $row) {
            $evidence = $this->evidenceOf($row);

            if ($evidence === null) {
                continue;
            }

            $kept[$index] = $row->withEvidence($evidence);
        }

        return $kept;
    }

    /**
     * Return what in the row's target gives the action, or null when nothing
     * does: a role, a permission whose name does not cover it, or a policy no
     * statement of which names it.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\ReviewRow  $row
     * @return \SineMacula\Laravel\Authorization\Reviews\ActionEvidence|null
     */
    private function evidenceOf(ReviewRow $row): ?ActionEvidence
    {
        $id = $row->target->id;

        return match (self::kindOf($row->sourceKind)) {
            GrantTarget::PERMISSION => $this->permissionEvidence($this->permissions[$id] ?? null, $row),
            GrantTarget::POLICY     => \array_key_exists($id, $this->policies) ? $this->policyEvidence($this->policies[$id], $row) : null,
            default                 => null,
        };
    }

    /**
     * Return the evidence of the permission the row holds when its name covers
     * the action; null when it does not, or the permission is gone.
     *
     * @param  array{name: string, guard: string|null}|null  $permission
     * @param  \SineMacula\Laravel\Authorization\Reviews\ReviewRow  $row
     * @return \SineMacula\Laravel\Authorization\Reviews\ActionEvidence|null
     */
    private function permissionEvidence(?array $permission, ReviewRow $row): ?ActionEvidence
    {
        if ($permission === null || HeldPermissions::match([$permission['name']], $this->action) === null) {
            return null;
        }

        return new ActionEvidence($this->action, EvidenceKind::PERMISSION, PolicyEffect::ALLOW, $this->reachOf($row), $permission['guard']);
    }

    /**
     * Return the evidence of the policy the row holds when a statement names
     * the action, or unreadable evidence when its document cannot be read.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Policy|null  $policy
     * @param  \SineMacula\Laravel\Authorization\Reviews\ReviewRow  $row
     * @return \SineMacula\Laravel\Authorization\Reviews\ActionEvidence|null
     */
    private function policyEvidence(?Policy $policy, ReviewRow $row): ?ActionEvidence
    {
        $reach = $this->reachOf($row);

        return $policy === null ? ActionEvidence::unreadable($this->action, $reach) : ActionStatements::evidence($policy, $this->action, $reach);
    }

    /**
     * Return where the row's route reaches: its origin scope; for a policy
     * through a role, where the role's grant and the attachment hold together,
     * unless either names half a tenant, when the half-named row's tenant
     * columns are shown as stored, still limited to the application either row
     * names.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\ReviewRow  $row
     * @return \SineMacula\Laravel\Authorization\Reviews\OriginScope
     *
     * @throws \UnexpectedValueException
     */
    private function reachOf(ReviewRow $row): OriginScope
    {
        $origin     = $row->originScope ?? throw new \UnexpectedValueException('A route of holdings starts from a stored grant.');
        $attachment = $row->sourceKind === SourceKind::ROLE_POLICY ? ($row->supportingGrants[1]->scope ?? null) : null;

        if ($attachment === null) {
            return $origin;
        }

        $overlap   = OriginScope::of($this->run->overlap(self::scopeOf($origin), self::scopeOf($attachment)));
        $malformed = self::malformedOf($origin, $attachment);

        return $malformed === null ? $overlap : new OriginScope($malformed->tenantType, $malformed->tenantId, $overlap->application, $malformed->includeSubtree);
    }

    /**
     * Return the one of a role's grant and its attachment that names half a
     * tenant, the grant first, or null when both name a whole tenant or none.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\OriginScope  $origin
     * @param  \SineMacula\Laravel\Authorization\Reviews\OriginScope  $attachment
     * @return \SineMacula\Laravel\Authorization\Reviews\OriginScope|null
     */
    private static function malformedOf(OriginScope $origin, OriginScope $attachment): ?OriginScope
    {
        return match (true) {
            $origin->isMalformed()     => $origin,
            $attachment->isMalformed() => $attachment,
            default                    => null,
        };
    }

    /**
     * Return the grant scope of a whole origin scope.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\OriginScope  $origin
     * @return \SineMacula\Laravel\Authorization\Support\GrantScope
     */
    private static function scopeOf(OriginScope $origin): GrantScope
    {
        return new GrantScope($origin->tenant(), $origin->application, $origin->includeSubtree);
    }

    /**
     * Return the kind of definition a route of the source holds that may give
     * an action: a permission or a policy; null for a role.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\Enums\SourceKind  $source
     * @return \SineMacula\Laravel\Authorization\Enums\GrantTarget|null
     */
    private static function kindOf(SourceKind $source): ?GrantTarget
    {
        return match ($source) {
            SourceKind::PERMISSION_GRANT, SourceKind::ROLE_PERMISSION => GrantTarget::PERMISSION,
            SourceKind::POLICY_ATTACHMENT, SourceKind::ROLE_POLICY    => GrantTarget::POLICY,
            default                                                   => null,
        };
    }

    /**
     * Return the name and guard of each permission with one of the keys, by its
     * key, read a chunk of the keys at a time.
     *
     * @param  array<array-key, string>  $keys
     * @return array<array-key, array{name: string, guard: string|null}>
     */
    private static function permissions(array $keys): array
    {
        [$table, $key] = Definitions::tableOf(GrantTarget::PERMISSION);
        $permissions   = [];

        foreach (\array_chunk($keys, GrantRows::CHUNK) as $chunk) {
            $read = AuthorizationConnection::connection()->table($table)->useWritePdo()->whereIn($key, $chunk)->get([$key . ' as id', 'name', 'guard']);

            foreach ($read as $row) {
                /** @var array{id: int|string, name: string, guard: string|null} $columns */
                $columns = (array) $row;

                $permissions[$columns['id']] = ['name' => $columns['name'], 'guard' => $columns['guard']];
            }
        }

        return $permissions;
    }

    /**
     * Return each policy with one of the keys, hydrated as a check reads it, by
     * its key, or null for one whose document cannot be read, read a chunk of
     * the keys at a time.
     *
     * @param  array<array-key, string>  $keys
     * @return array<array-key, \SineMacula\Laravel\Authorization\Evaluation\Policy|null>
     */
    private static function policies(array $keys): array
    {
        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Policy> $class */
        $class    = ModelClasses::get(GrantTarget::POLICY->value);
        $policies = [];

        foreach (\array_chunk($keys, GrantRows::CHUNK) as $chunk) {
            foreach ($class::query()->withoutGlobalScopes()->useWritePdo()->whereKey($chunk)->get() as $stored) {
                /** @var int|string $key */
                $key = $stored->getKey();

                try {
                    $policies[$key] = PolicyDocument::hydrate($stored);
                } catch (InvalidPolicyDocumentException) {
                    $policies[$key] = null;
                }
            }
        }

        return $policies;
    }
}
