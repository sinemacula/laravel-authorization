<?php

declare(strict_types = 1);

namespace Tests\Unit\Contracts;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Contracts\QueryableResource;
use SineMacula\Laravel\Authorization\Support\ResourceTenancy;
use Tests\Fixtures\QueryScoping\ScopedTicket;

/**
 * Unit tests for the contract of a model whose queries can be scoped.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class QueryableResourceTest extends TestCase
{
    /**
     * The contract declares one static method, the model's tenancy, which a
     * model answers without a record.
     *
     * @return void
     */
    public function testItDeclaresTheModelsTenancyStatically(): void
    {
        $methods = (new \ReflectionClass(QueryableResource::class))->getMethods();

        self::assertCount(1, $methods);
        self::assertSame('resourceTenancy', $methods[0]->getName());
        self::assertTrue($methods[0]->isStatic());
        self::assertSame(ResourceTenancy::class, (string) $methods[0]->getReturnType());
        self::assertSame(['team_id'], ScopedTicket::resourceTenancy()->columnNames());
    }
}
