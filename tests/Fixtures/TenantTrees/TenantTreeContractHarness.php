<?php

declare(strict_types = 1);

namespace Tests\Fixtures\TenantTrees;

use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Testing\Concerns\TenantTreeContract;

/**
 * Runs the tenant tree contract's checks on the tree and fixture given, outside
 * a test case of its own, so a test can run them on a broken tree and read the
 * failure. It overrides each of the kit's hooks, as a host test case may, and
 * falls back to the kit's own through an alias.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class TenantTreeContractHarness
{
    use TenantTreeContract {
        tenantTreeConnection as private packageConnection;
        hasMixedTenantTypes as private claimsMixedTypes;
        tenantTreeOutsider as private kitOutsider;
    }

    /**
     * Create a new harness for the tree.
     *
     * @param  \SineMacula\Laravel\Authorization\Contracts\TenantTree  $tree
     * @param  list<array{0: \SineMacula\Laravel\Authorization\Support\Reference, 1: \SineMacula\Laravel\Authorization\Support\Reference|null}>  $nodes
     * @param  false|string|null  $connection
     * @param  bool|null  $isMixed
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $outsider
     */
    public function __construct(

        /** The tree under test. */
        private TenantTree $tree,

        /** The fixture the tree was seeded with. */
        private array $nodes,

        /** The connection the subtree must be on; false for the kit's default. */
        private false|string|null $connection = false,

        /** Whether the tree claims mixed types; null for the kit's default. */
        private ?bool $isMixed = null,

        /** The tenant outside the fixture; null for the kit's default. */
        private ?Reference $outsider = null,
    ) {}

    /**
     * Return the tenant outside the fixture the checks ask the tree about.
     *
     * @return \SineMacula\Laravel\Authorization\Support\Reference
     */
    public function outsideTenant(): Reference
    {
        return $this->tenantTreeOutsider();
    }

    /**
     * Return the tree under test.
     *
     * @return \SineMacula\Laravel\Authorization\Contracts\TenantTree
     */
    #[\Override]
    protected function tenantTree(): TenantTree
    {
        return $this->tree;
    }

    /**
     * Return the fixture the tree was seeded with.
     *
     * @return list<array{0: \SineMacula\Laravel\Authorization\Support\Reference, 1: \SineMacula\Laravel\Authorization\Support\Reference|null}>
     */
    #[\Override]
    protected function tenantTreeNodes(): array
    {
        return $this->nodes;
    }

    /**
     * Return the connection the subtree must be on.
     *
     * @return string|null
     */
    protected function tenantTreeConnection(): ?string
    {
        return $this->connection === false ? $this->packageConnection() : $this->connection;
    }

    /**
     * Determine whether the tree claims mixed types.
     *
     * @return bool
     */
    protected function hasMixedTenantTypes(): bool
    {
        return $this->isMixed ?? $this->claimsMixedTypes();
    }

    /**
     * Return the tenant outside the fixture.
     *
     * @return \SineMacula\Laravel\Authorization\Support\Reference
     */
    protected function tenantTreeOutsider(): Reference
    {
        return $this->outsider ?? $this->kitOutsider();
    }
}
