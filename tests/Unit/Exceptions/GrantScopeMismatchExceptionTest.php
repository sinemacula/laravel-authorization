<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Exceptions\GrantScopeMismatchException;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Unit tests for the refusal of a grant outside the tenant that owns its
 * target.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(GrantScopeMismatchException::class)]
final class GrantScopeMismatchExceptionTest extends TestCase
{
    /**
     * The message names the record, its owner and where the grant would have
     * held, and the accessors return each.
     *
     * @return void
     */
    public function testNamesTheRecordItsOwnerAndTheScope(): void
    {
        $owner     = new Reference('organisation', 'org-a');
        $elsewhere = new Reference('organisation', 'org-b');

        $inAnother = new GrantScopeMismatchException('role', 'editor', $owner, $elsewhere);
        $platform  = new GrantScopeMismatchException('permission', 'posts:edit', $owner, null);

        self::assertSame(
            'The role \'editor\' belongs to tenant \'organisation:org-a\' and can only be granted there, not in tenant \'organisation:org-b\'.',
            $inAnother->getMessage(),
        );
        self::assertSame('The permission \'posts:edit\' belongs to tenant \'organisation:org-a\' and can only be granted there, not platform-wide.', $platform->getMessage());
        self::assertSame('role', $inAnother->getKind());
        self::assertSame('editor', $inAnother->getName());
        self::assertSame($owner, $inAnother->getOwner());
        self::assertSame($elsewhere, $inAnother->getScope());
        self::assertNull($platform->getScope());
    }
}
