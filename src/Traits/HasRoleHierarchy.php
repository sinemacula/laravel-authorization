<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Traits;

use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Support\Collection;
use SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException;
use SineMacula\Laravel\Authorization\Models\Role;

/**
 * Role hierarchy and rank-comparison behaviour.
 *
 * Walks the `parent_id` chain in both directions with cycle detection,
 * and exposes the rank-comparison helpers (`outranks`,
 * `outranksOrEquals`, `isRanked`) that the RBAC guard uses when
 * deciding whether one role may act on another. Extracted from `Role`
 * so the model keeps to schema, relations, and lifecycle.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @phpstan-require-extends \SineMacula\Laravel\Authorization\Models\Role
 */
trait HasRoleHierarchy // @phpstan-ignore trait.unused
{
    /**
     * The parent role in the hierarchy.
     *
     * A null `parent_id` marks this role as a root (no parent).
     *
     * @return \Illuminate\Database\Eloquent\Relations\BelongsTo<\SineMacula\Laravel\Authorization\Models\Role, $this>
     */
    public function parent(): BelongsTo
    {
        return $this->belongsTo(Role::class, 'parent_id');
    }

    /**
     * The direct children of this role in the hierarchy.
     *
     * @return \Illuminate\Database\Eloquent\Relations\HasMany<\SineMacula\Laravel\Authorization\Models\Role, $this>
     */
    public function children(): HasMany
    {
        return $this->hasMany(Role::class, 'parent_id');
    }

    /**
     * Return all ancestor roles ordered from root to immediate parent.
     *
     * Walks up the parent chain eagerly loading each level. Includes
     * cycle detection — if a visited role is encountered a second
     * time, the chain is broken and a `RoleHierarchyCycleException`
     * is thrown carrying the offending role's name and the name of
     * the parent that would close the cycle.
     *
     * @return \Illuminate\Support\Collection<int, \SineMacula\Laravel\Authorization\Models\Role>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException
     */
    public function ancestors(): Collection
    {
        $ancestors = new Collection;
        $visited   = [];
        $current   = $this;

        while ($current->parent_id !== null) {
            if (isset($visited[$current->parent_id])) {
                /** @var static|null $proposedParent */
                $proposedParent = static::query()->find($current->parent_id);
                /** @var string $parentId */
                $parentId     = $current->parent_id;
                $proposedName = $proposedParent === null ? $parentId : $proposedParent->name;

                throw new RoleHierarchyCycleException(roleName: $this->name, proposedParentName: $proposedName);
            }

            $visited[$current->parent_id] = true;

            /** @var \SineMacula\Laravel\Authorization\Models\Role|null $parent */
            $parent = $current->parent;

            if ($parent === null) {
                break;
            }

            $ancestors->prepend($parent);
            $current = $parent;
        }

        return $ancestors->values();
    }

    /**
     * Return all descendant roles (breadth-first).
     *
     * Carries a visited set keyed by primary key so a corrupted
     * hierarchy (cycle written via raw SQL, a race between two
     * concurrent `parent_id` saves, FK enforcement disabled) does
     * not turn the walk into a runaway loop. A re-encountered node
     * raises `RoleHierarchyCycleException` — matching the
     * ancestors-walk behaviour so callers have one exception to
     * catch regardless of direction.
     *
     * @return \Illuminate\Support\Collection<int, \SineMacula\Laravel\Authorization\Models\Role>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException
     */
    public function descendants(): Collection
    {
        $descendants = new Collection;
        $queue       = $this->children()->get()->all();

        /** @var string $selfKey */
        $selfKey = $this->getKey();
        $visited = [$selfKey => true];

        while ($queue !== []) {
            /** @var \SineMacula\Laravel\Authorization\Models\Role $node */
            $node = \array_shift($queue);

            /** @var string $nodeId */
            $nodeId = $node->getKey();

            if (isset($visited[$nodeId])) {
                throw new RoleHierarchyCycleException(roleName: $this->name, proposedParentName: $node->name);
            }

            $visited[$nodeId] = true;
            $descendants->push($node);

            foreach ($node->children()->get() as $child) {
                $queue[] = $child;
            }
        }

        return $descendants->values();
    }

    /**
     * Determine whether this role is a descendant of the given role.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @return bool
     */
    public function isDescendantOf(Role $role): bool
    {
        return $role->isAncestorOf($this);
    }

    /**
     * Determine whether this role is an ancestor of the given role.
     *
     * Delegates to the other role's `ancestors()` walk so cycle
     * detection has a single owner — any corrupted chain raises
     * `RoleHierarchyCycleException` from `ancestors()` rather than
     * looping forever.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @return bool
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException
     */
    public function isAncestorOf(Role $role): bool
    {
        /** @var string $selfKey */
        $selfKey = $this->getKey();

        foreach ($role->ancestors() as $ancestor) {
            /** @var string $ancestorKey */
            $ancestorKey = $ancestor->getKey();

            if ($ancestorKey === $selfKey) {
                return true;
            }
        }

        return false;
    }

    /**
     * Determine whether this role carries a rank value.
     *
     * Unranked roles (`rank === null`) are not subject to rank-based
     * seniority checks.
     *
     * @return bool
     */
    public function isRanked(): bool
    {
        return $this->rank !== null;
    }

    /**
     * Determine whether this role outranks the given role.
     *
     * A lower numeric rank is more senior (0 = most senior). Both
     * roles must be ranked; if either is unranked the comparison is
     * undefined and the method returns false.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $other
     * @return bool
     */
    public function outranks(Role $other): bool
    {
        if (!$this->isRanked() || !$other->isRanked()) {
            return false;
        }

        /** @var int $thisRank */
        $thisRank = $this->rank;

        /** @var int $otherRank */
        $otherRank = $other->rank;

        return $thisRank < $otherRank;
    }

    /**
     * Determine whether this role outranks or equals the given role.
     *
     * Same semantics as `outranks()` but uses `<=` (equal rank
     * satisfies the check). Both roles must be ranked; if either is
     * unranked the method returns false.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $other
     * @return bool
     */
    public function outranksOrEquals(Role $other): bool
    {
        if (!$this->isRanked() || !$other->isRanked()) {
            return false;
        }

        /** @var int $thisRank */
        $thisRank = $this->rank;

        /** @var int $otherRank */
        $otherRank = $other->rank;

        return $thisRank <= $otherRank;
    }
}
