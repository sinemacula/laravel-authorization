<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Exceptions\InlinePolicyAttachmentException;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Unit tests for the refusal of an inline policy attached to a grantee it does
 * not belong to.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(InlinePolicyAttachmentException::class)]
final class InlinePolicyAttachmentExceptionTest extends TestCase
{
    /**
     * The refusal names the policy, the grantee it belongs to and the one it
     * was to be attached to.
     *
     * @return void
     */
    public function testTheRefusalNamesThePolicyAndBothGrantees(): void
    {
        $owner     = new Reference('user', '1');
        $grantee   = new Reference('role', 'editor-id');
        $exception = new InlinePolicyAttachmentException('mine', $owner, $grantee);

        self::assertSame('Inline policy \'mine\' belongs to user:1 and is attached to it alone, not to role:editor-id.', $exception->getMessage());
        self::assertSame('mine', $exception->getPolicyName());
        self::assertSame($owner, $exception->getOwner());
        self::assertSame($grantee, $exception->getGrantee());
        self::assertInstanceOf(\LogicException::class, $exception);
    }
}
