<?php

declare(strict_types = 1);

namespace Tests\Unit\Administration;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Administration\FurtherChecks;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResourceReference;

/**
 * Unit tests for `FurtherChecks`, what the administration stage may ask of the
 * decision pipeline.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FurtherChecks::class)]
final class FurtherChecksTest extends TestCase
{
    /**
     * The checks carry the subject and the origin, decide each further check
     * through the pipeline's callback, on the resource given or none, and
     * gather each check's sources through the other.
     *
     * @return void
     */
    public function testItAsksThePipeline(): void
    {
        $subject  = new Subject(new \stdClass);
        $origin   = new Reference('tenant', 'a');
        $decision = Decision::allow(DecisionStage::ALLOW);
        $resource = ResourceReference::record('post', '1');
        $asked    = [];
        $checks   = new FurtherChecks(
            $subject,
            $origin,
            static function (string $action, ?ResourceReference $on) use (&$asked, $decision): Decision {
                $asked[] = [$action, $on];

                return $decision;
            },
            static function (string $action) use (&$asked): null {
                $asked[] = [$action];

                return null;
            },
        );

        self::assertSame($subject, $checks->subject);
        self::assertSame($origin, $checks->origin);
        self::assertSame($decision, $checks->decide('posts:edit', $resource));
        self::assertSame($decision, $checks->decide('posts:read'));
        self::assertNull($checks->sources('posts:edit'));
        self::assertSame([['posts:edit', $resource], ['posts:read', null], ['posts:edit']], $asked);
    }
}
