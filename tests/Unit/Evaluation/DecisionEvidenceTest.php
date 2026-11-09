<?php

declare(strict_types = 1);

namespace Tests\Unit\Evaluation;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Evaluation\DecisionEvidence;
use SineMacula\Laravel\Authorization\Evaluation\DecisionProvenance;
use SineMacula\Laravel\Authorization\Evaluation\ExplanationRequest;
use SineMacula\Laravel\Authorization\Evaluation\GrantProvenance;

/**
 * Unit tests for the decision evidence value object.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DecisionEvidence::class)]
final class DecisionEvidenceTest extends TestCase
{
    /**
     * Evidence defaults to no grant and no request.
     *
     * @return void
     */
    public function testDefaults(): void
    {
        $evidence = new DecisionEvidence;

        self::assertSame([], $evidence->grants);
        self::assertNull($evidence->request);
    }

    /**
     * withRequest() keeps the grants and adds the request, leaving the original
     * unchanged.
     *
     * @return void
     */
    public function testWithRequestKeepsTheGrants(): void
    {
        $grants   = [GrantProvenance::unavailable('posts:read')];
        $request  = new ExplanationRequest('posts:read', null, new DecisionProvenance, new DecisionProvenance);
        $evidence = new DecisionEvidence($grants);
        $with     = $evidence->withRequest($request);

        self::assertSame($grants, $with->grants);
        self::assertSame($request, $with->request);
        self::assertNull($evidence->request);
    }
}
