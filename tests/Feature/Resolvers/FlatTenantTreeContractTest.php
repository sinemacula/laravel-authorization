<?php

declare(strict_types = 1);

namespace Tests\Feature\Resolvers;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Resolvers\FlatTenantTree;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Testing\Concerns\TenantTreeContract;
use Tests\TestCase;

/**
 * The tenant tree contract, kept by the default, flat tree, over a few tenants
 * at the top, of two types whose ids clash. It claims no mixed types, the kit's
 * default: a fixture with no tenant below another cannot catch a subtree that
 * confuses types, so the kit refuses it for a tree claiming them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FlatTenantTree::class)]
#[CoversTrait(TenantTreeContract::class)]
final class FlatTenantTreeContractTest extends TestCase
{
    use TenantTreeContract;

    /**
     * Return the tree under test, which needs no rows.
     *
     * @return \SineMacula\Laravel\Authorization\Contracts\TenantTree
     */
    #[\Override]
    protected function tenantTree(): TenantTree
    {
        return new FlatTenantTree;
    }

    /**
     * Return the fixture: four tenants, none with a parent.
     *
     * @return list<array{0: \SineMacula\Laravel\Authorization\Support\Reference, 1: \SineMacula\Laravel\Authorization\Support\Reference|null}>
     */
    #[\Override]
    protected function tenantTreeNodes(): array
    {
        return [
            [new Reference('stub_tenant', '1'), null],
            [new Reference('stub_tenant', '2'), null],
            [new Reference('stub_org', '1'), null],
            [new Reference('stub_org', '3'), null],
        ];
    }
}
