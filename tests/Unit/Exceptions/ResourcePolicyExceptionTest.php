<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Exceptions\ResourcePolicyException;

/**
 * Unit tests for the refusal of a policy attached, or rewritten, against the
 * rule for its statements' `principals`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ResourcePolicyException::class)]
final class ResourcePolicyExceptionTest extends TestCase
{
    /**
     * An inline policy is refused by name, with no statements.
     *
     * @return void
     */
    public function testInline(): void
    {
        $exception = ResourcePolicyException::inline('mine');

        self::assertInstanceOf(\LogicException::class, $exception);
        self::assertSame('Inline policy \'mine\' belongs to one grantee and cannot be attached to a resource; attach a managed policy.', $exception->getMessage());
        self::assertSame('mine', $exception->getPolicyName());
        self::assertSame([], $exception->getStatements());
    }

    /**
     * A resource policy's allows naming no principals are named by position.
     *
     * @return void
     */
    public function testPrincipalsRequired(): void
    {
        $exception = ResourcePolicyException::principalsRequired('sharing', [0, 2]);

        self::assertSame('Policy \'sharing\' is attached to a resource, so every allow statement names its principals; statement #0, #2 name none.', $exception->getMessage());
        self::assertSame('sharing', $exception->getPolicyName());
        self::assertSame([0, 2], $exception->getStatements());
    }

    /**
     * A grantee's policy's statements naming principals are named by position.
     *
     * @return void
     */
    public function testPrincipalsRefused(): void
    {
        $exception = ResourcePolicyException::principalsRefused('own', [1]);

        $message = 'Policy \'own\' is attached to a grantee or a role, so no statement names principals, which only a resource policy\'s allows do; statement #1 name some.';

        self::assertSame($message, $exception->getMessage());
        self::assertSame('own', $exception->getPolicyName());
        self::assertSame([1], $exception->getStatements());
    }
}
