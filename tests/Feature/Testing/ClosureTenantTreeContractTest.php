<?php

declare(strict_types = 1);

namespace Tests\Feature\Testing;

use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Testing\Concerns\TenantTreeContract;
use Tests\Fixtures\QueryScoping\ClosureTenantTree;
use Tests\Fixtures\TenantTrees\ClashingTenants;
use Tests\TestCase;

/**
 * The tenant tree contract, kept by the closure-table tree the query scoping
 * tests use, over a fixture of two types whose ids clash.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversTrait(TenantTreeContract::class)]
final class ClosureTenantTreeContractTest extends TestCase
{
    use TenantTreeContract;

    /**
     * Seed the closure table with the fixture.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        ClashingTenants::seed();
    }

    /**
     * Return the tree under test.
     *
     * @return \SineMacula\Laravel\Authorization\Contracts\TenantTree
     */
    #[\Override]
    protected function tenantTree(): TenantTree
    {
        return new ClosureTenantTree;
    }

    /**
     * Return the fixture the tree was seeded with.
     *
     * @return list<array{0: \SineMacula\Laravel\Authorization\Support\Reference, 1: \SineMacula\Laravel\Authorization\Support\Reference|null}>
     */
    #[\Override]
    protected function tenantTreeNodes(): array
    {
        return ClashingTenants::nodes();
    }

    /**
     * Claim mixed types: the fixture's teams and organisations share ids.
     *
     * @return bool
     */
    protected function hasMixedTenantTypes(): bool
    {
        return true;
    }
}
