<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Exceptions\UnresolvedSubjectException;

/**
 * Unit tests for the refusal of a saved subject reference a console subject
 * resolver cannot resolve: malformed, of no model type, of no row, of a model
 * that cannot be checked, or ambiguous.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(UnresolvedSubjectException::class)]
final class UnresolvedSubjectExceptionTest extends TestCase
{
    /**
     * Each refusal is an invalid argument naming the reference, or its type,
     * and what is wrong with it.
     *
     * @return void
     */
    public function testEachRefusalNamesWhatIsWrong(): void
    {
        $refusals = [
            'The subject must be in the format {morphType}:{key} (e.g. user:1).'                                   => UnresolvedSubjectException::malformed(),
            'The subject type \'team\' is not an Eloquent model.'                                                  => UnresolvedSubjectException::unknownType('team'),
            'No subject \'user:1\' was found.'                                                                     => UnresolvedSubjectException::notFound('user:1'),
            'The subject \'user:2\' cannot be checked: its principal is not a saved authorizable identity.'        => UnresolvedSubjectException::unsupported('user:2'),
            'The subject \'user:3\' is ambiguous: the subject resolver maps it to a subject that is not about it.' => UnresolvedSubjectException::ambiguous('user:3'),
        ];

        foreach ($refusals as $message => $exception) {
            self::assertSame($message, $exception->getMessage());
            self::assertSame(0, $exception->getCode());
            self::assertNull($exception->getPrevious());
            self::assertInstanceOf(\InvalidArgumentException::class, $exception);
        }
    }

    /**
     * A subject that failed to resolve is refused naming neither the reference
     * nor the failure, which is kept as the previous exception.
     *
     * @return void
     */
    public function testAFailureIsKeptButNotNamed(): void
    {
        $failure   = new \RuntimeException('sentinel-failure-61d0', 7);
        $exception = UnresolvedSubjectException::unresolvable($failure);

        self::assertSame('The subject could not be resolved.', $exception->getMessage());
        self::assertSame(0, $exception->getCode());
        self::assertSame($failure, $exception->getPrevious());
        self::assertInstanceOf(\InvalidArgumentException::class, $exception);
    }
}
