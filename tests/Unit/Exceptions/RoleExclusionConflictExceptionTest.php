<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Exceptions\RoleExclusionConflictException;
use SineMacula\Laravel\Authorization\Exclusions\ConflictReport;
use SineMacula\Laravel\Authorization\Exclusions\ExclusionConflict;
use SineMacula\Laravel\Authorization\Exclusions\ExclusionRoute;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Unit tests for the refusal of a pair someone holds both roles of.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RoleExclusionConflictException::class)]
final class RoleExclusionConflictExceptionTest extends TestCase
{
    /**
     * The refusal carries the report and names the roles and how many hold
     * both, one holder or several.
     *
     * @return void
     */
    public function testCarriesTheReport(): void
    {
        $route = new ExclusionRoute(new Reference('user', '1'), new Reference('role', 'a'), [new Reference('role', 'a')], GrantScope::platform(), GrantScope::platform());
        $one   = new ConflictReport(new Reference('role', 'a'), new Reference('role', 'b'), [new ExclusionConflict(new Reference('user', '1'), null, $route, $route)]);
        $two   = new ConflictReport(new Reference('role', 'a'), new Reference('role', 'b'), [
            new ExclusionConflict(new Reference('user', '1'), null, $route, $route),
            new ExclusionConflict(new Reference('user', '2'), null, $route, $route),
        ]);
        $single = new RoleExclusionConflictException($one, 'clerk', 'auditor');
        $plural = new RoleExclusionConflictException($two, 'clerk', 'auditor');

        self::assertInstanceOf(\RuntimeException::class, $single);
        self::assertSame($one, $single->getReport());
        self::assertSame(
            'Roles \'clerk\' and \'auditor\' cannot be declared mutually exclusive: 1 holder holds both where their reach overlaps; resolve every conflict first.',
            $single->getMessage(),
        );
        self::assertSame(
            'Roles \'clerk\' and \'auditor\' cannot be declared mutually exclusive: 2 holders hold both where their reach overlaps; resolve every conflict first.',
            $plural->getMessage(),
        );
    }
}
