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
     * and what is wrong with it, its code saying which refusal it is.
     *
     * @return void
     */
    public function testEachRefusalNamesWhatIsWrong(): void
    {
        $refusals = [
            UnresolvedSubjectException::MALFORMED    => [UnresolvedSubjectException::malformed(), 'The subject must be in the format {morphType}:{key} (e.g. user:1).'],
            UnresolvedSubjectException::UNKNOWN_TYPE => [UnresolvedSubjectException::unknownType('team'), 'The subject type \'team\' is not an Eloquent model.'],
            UnresolvedSubjectException::NOT_FOUND    => [UnresolvedSubjectException::notFound('user:1'), 'No subject \'user:1\' was found.'],
            UnresolvedSubjectException::UNSUPPORTED  => [
                UnresolvedSubjectException::unsupported('user:2'),
                'The subject \'user:2\' cannot be checked: its principal is not a saved authorizable identity.',
            ],
            UnresolvedSubjectException::AMBIGUOUS => [
                UnresolvedSubjectException::ambiguous('user:3'),
                'The subject \'user:3\' is ambiguous: the subject resolver maps it to a subject that is not about it.',
            ],
        ];

        foreach ($refusals as $code => [$exception, $message]) {
            self::assertSame($message, $exception->getMessage());
            self::assertSame($code, $exception->getCode());
            self::assertNull($exception->getPrevious());
            self::assertInstanceOf(\InvalidArgumentException::class, $exception);
        }

        self::assertCount(6, \array_unique([...\array_keys($refusals), UnresolvedSubjectException::UNRESOLVABLE]));
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
        self::assertSame(UnresolvedSubjectException::UNRESOLVABLE, $exception->getCode());
        self::assertSame($failure, $exception->getPrevious());
        self::assertInstanceOf(\InvalidArgumentException::class, $exception);
    }

    /**
     * A refusal as a command writes it names the argument alone, never the
     * reference or its type, keeping its code and the refusal as the previous
     * exception; a refusal of any other code is one that could not be resolved.
     *
     * @return void
     */
    public function testARefusalNamesTheArgumentAlone(): void
    {
        $refusals = [
            'The reference must be in the format {morphType}:{key} (e.g. user:1).'                        => UnresolvedSubjectException::malformed(),
            'The reference\'s type is not an Eloquent model.'                                             => UnresolvedSubjectException::unknownType('sentinel'),
            'The reference names no saved row.'                                                           => UnresolvedSubjectException::notFound('user:sentinel'),
            'The reference cannot be checked: its principal is not a saved authorizable identity.'        => UnresolvedSubjectException::unsupported('user:sentinel'),
            'The reference is ambiguous: the subject resolver maps it to a subject that is not about it.' => UnresolvedSubjectException::ambiguous('user:sentinel'),
        ];

        $refusals['The reference could not be resolved.'] = UnresolvedSubjectException::unresolvable(new \RuntimeException('sentinel'));

        foreach ($refusals as $message => $refusal) {
            $named = $refusal->namingOnly('reference');

            self::assertSame($message, $named->getMessage());
            self::assertSame([$refusal->getCode(), $refusal], [$named->getCode(), $named->getPrevious()]);
            self::assertStringNotContainsString('sentinel', $named->getMessage());
        }

        foreach ([new UnresolvedSubjectException('No user:sentinel here.'), new UnresolvedSubjectException('user:sentinel', 99)] as $own) {
            self::assertSame('The subject could not be resolved.', $own->namingOnly('subject')->getMessage());
        }
    }
}
