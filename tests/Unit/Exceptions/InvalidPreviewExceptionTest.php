<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Exceptions\InvalidPreviewException;

/**
 * Unit tests for the refusal of what a preview does not do in this version: a
 * change of target or scope, a policy override, and a target that names no
 * record.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(InvalidPreviewException::class)]
final class InvalidPreviewExceptionTest extends TestCase
{
    /**
     * Each refusal is a logic error naming what was asked and what to do
     * instead, and nothing about the target.
     *
     * @return void
     */
    public function testEachRefusalNamesWhatWasAsked(): void
    {
        $refusals = [
            'A preview cannot change its target through for(); build a new preview with Authorization::previewFor().'              => InvalidPreviewException::retargeted('for'),
            'A preview lists only in the tenant and application it was built for; build a new preview for another scope.'          => InvalidPreviewException::rescoped(),
            'A preview decides through the stored policies alone; withPolicies() cannot be combined with previewFor().'            => InvalidPreviewException::hypothetical(),
            'A preview needs a target that names a record, a model or a tenant with a key, so every preview decision can name it.' => InvalidPreviewException::unidentified(),
        ];

        foreach ($refusals as $message => $exception) {
            self::assertSame($message, $exception->getMessage());
            self::assertSame(0, $exception->getCode());
            self::assertNull($exception->getPrevious());
            self::assertInstanceOf(\LogicException::class, $exception);
        }
    }
}
