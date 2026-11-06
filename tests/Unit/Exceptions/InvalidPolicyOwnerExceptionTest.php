<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Exceptions\InvalidPolicyOwnerException;

/**
 * Unit tests for the refusal of a policy with one owner column and not the
 * other.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(InvalidPolicyOwnerException::class)]
final class InvalidPolicyOwnerExceptionTest extends TestCase
{
    /**
     * The refusal names the policy and the missing column.
     *
     * @return void
     */
    public function testTheRefusalNamesThePolicyAndTheMissingColumn(): void
    {
        $exception = new InvalidPolicyOwnerException('mine', 'owner_id');

        self::assertSame(
            'Cannot save policy \'mine\' with inconsistent owner columns: \'owner_id\' is required when the other owner column is set. '
            . 'Both columns must be null (a managed policy) or both must be set (an inline policy).',
            $exception->getMessage(),
        );
        self::assertSame('mine', $exception->getPolicyName());
        self::assertSame('owner_id', $exception->getMissingColumn());
        self::assertInstanceOf(\LogicException::class, $exception);
    }
}
