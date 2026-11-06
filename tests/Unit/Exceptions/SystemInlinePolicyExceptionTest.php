<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Exceptions\SystemInlinePolicyException;

/**
 * Unit tests for the refusal of an inline policy saved as a system policy.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SystemInlinePolicyException::class)]
final class SystemInlinePolicyExceptionTest extends TestCase
{
    /**
     * The refusal names the policy.
     *
     * @return void
     */
    public function testTheRefusalNamesThePolicy(): void
    {
        $exception = new SystemInlinePolicyException('mine');

        self::assertSame(
            'Cannot save inline policy \'mine\' as a system policy: an inline policy is deleted with its grantee, so only a managed policy can be a system one.',
            $exception->getMessage(),
        );
        self::assertSame('mine', $exception->getPolicyName());
        self::assertInstanceOf(\LogicException::class, $exception);
    }
}
