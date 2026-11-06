<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Exceptions\OwnerChangedException;

/**
 * Unit tests for the refusal of a change to a record's owner.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(OwnerChangedException::class)]
final class OwnerChangedExceptionTest extends TestCase
{
    /**
     * A change of owner names the record.
     *
     * @return void
     */
    public function testAChangeOfOwnerNamesTheRecord(): void
    {
        $exception = new OwnerChangedException('role', 'editor');

        self::assertSame('The owner of role \'editor\' is fixed once it is created; create the role in the new owner instead.', $exception->getMessage());
        self::assertSame('role', $exception->getKind());
        self::assertSame('editor', $exception->getName());
        self::assertSame('tenant', $exception->getOwnerKind());
    }

    /**
     * A change of the grantee an inline policy belongs to names the policy and
     * points at a policy for the new grantee.
     *
     * @return void
     */
    public function testAChangeOfGranteeNamesTheInlinePolicy(): void
    {
        $exception = new OwnerChangedException('policy', 'mine', 'grantee');

        self::assertSame(
            'The grantee of inline policy \'mine\' is fixed once it is created; create an inline policy for the new grantee instead.',
            $exception->getMessage(),
        );
        self::assertSame('policy', $exception->getKind());
        self::assertSame('mine', $exception->getName());
        self::assertSame('grantee', $exception->getOwnerKind());
    }
}
