<?php

declare(strict_types = 1);

namespace Tests\Unit\Evaluation;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Evaluation\HeldPermission;

/**
 * Unit tests for an action a listing holds, with the authentication
 * requirements its decision read.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(HeldPermission::class)]
final class HeldPermissionTest extends TestCase
{
    /**
     * An action whose decision read no requirement is held unconditionally.
     *
     * @return void
     */
    public function testAnActionReadingNoRequirementIsUnconditional(): void
    {
        $held = new HeldPermission('posts:create');

        self::assertSame('posts:create', $held->action);
        self::assertSame([], $held->requirements);
        self::assertTrue($held->isUnconditional());
        self::assertTrue((new HeldPermission('posts:create', []))->isUnconditional());
    }

    /**
     * An action whose decision read requirements is conditional, and names each
     * once, sorted, whatever order they were given in.
     *
     * @return void
     */
    public function testRequirementsAreKeptOnceSortedAndMakeItConditional(): void
    {
        $held = new HeldPermission('posts:delete', ['phishing_resistant', 'multifactor', 'assurance_level', 'multifactor']);

        self::assertSame('posts:delete', $held->action);
        self::assertSame(['assurance_level', 'multifactor', 'phishing_resistant'], $held->requirements);
        self::assertFalse($held->isUnconditional());
        self::assertSame(['multifactor'], (new HeldPermission('posts:delete', [3 => 'multifactor']))->requirements);
    }
}
