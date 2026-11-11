<?php

declare(strict_types = 1);

namespace Tests\Fixtures\TenantTrees;

use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Fixtures\QueryScoping\ClosureTenantTree;

/**
 * A tenant tree of two types whose ids clash, for the tenant tree contract
 * tests: an organisation above three teams, one below another, and an account
 * listed last, so neither the fixture nor the rows seeded are in the order of
 * their keys; and a second organisation, sharing its id with one of the teams,
 * above a fourth team.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ClashingTenants
{
    /**
     * Return each node of the tree and its parent, or null for a tenant at the
     * top, every parent before its children.
     *
     * @return list<array{0: \SineMacula\Laravel\Authorization\Support\Reference, 1: \SineMacula\Laravel\Authorization\Support\Reference|null}>
     */
    public static function nodes(): array
    {
        return [
            [new Reference('org', '1'), null],
            [new Reference('team', '1'), new Reference('org', '1')],
            [new Reference('team', '2'), new Reference('org', '1')],
            [new Reference('team', '7'), new Reference('team', '2')],
            [new Reference('org', '7'), null],
            [new Reference('team', '8'), new Reference('org', '7')],
            [new Reference('account', '3'), new Reference('org', '1')],
        ];
    }

    /**
     * Seed the tree into the closure table.
     *
     * @return void
     */
    public static function seed(): void
    {
        foreach (self::nodes() as [$node, $parent]) {
            ClosureTenantTree::add($node, $parent);
        }
    }
}
