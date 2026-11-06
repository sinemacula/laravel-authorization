<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Exceptions\AuthorizationException;
use SineMacula\Laravel\Authorization\Exceptions\QueryScopeRefusedException;
use SineMacula\Laravel\Authorization\Query\Enums\RefusalReason;
use SineMacula\Laravel\Authorization\Query\Refusal;

/**
 * Unit tests for the exception a refused query scope throws.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(QueryScopeRefusedException::class)]
final class QueryScopeRefusedExceptionTest extends TestCase
{
    /**
     * The exception carries the action, the type and every refusal, and its
     * message names each refusal in order; it is a runtime fault, never an
     * authorization denial.
     *
     * @return void
     */
    public function testTheExceptionNamesEveryRefusal(): void
    {
        $refusals  = [new Refusal(RefusalReason::RESOURCE_PATTERN, 'p', 'p#0'), new Refusal(RefusalReason::RECORD_ATTACHMENT, 'q[2]')];
        $exception = new QueryScopeRefusedException('posts:view', 'posts', $refusals);

        self::assertSame('posts:view', $exception->action);
        self::assertSame('posts', $exception->resourceType);
        self::assertSame($refusals, $exception->refusals);
        self::assertSame([RefusalReason::RESOURCE_PATTERN, RefusalReason::RECORD_ATTACHMENT], $exception->reasons());
        $message = 'whereAuthorized(\'posts:view\') cannot be compiled exactly for \'posts\': '
            . 'resource_pattern (statement p#0); record_attachment (statement q[2]).';

        self::assertSame($message, $exception->getMessage());
        self::assertInstanceOf(\RuntimeException::class, $exception);
        self::assertNotInstanceOf(AuthorizationException::class, $exception);
    }

    /**
     * A single refusal makes an exception of its own.
     *
     * @return void
     */
    public function testASingleRefusalMakesAnException(): void
    {
        $refusal   = new Refusal(RefusalReason::DRIVER, null, null, 'mariadb');
        $exception = QueryScopeRefusedException::of('posts:view', 'posts', $refusal);

        self::assertSame([$refusal], $exception->refusals);
        self::assertStringEndsWith('\'posts\': driver (key mariadb).', $exception->getMessage());
    }
}
