<?php

declare(strict_types = 1);

namespace Tests\Unit\Events;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\EvaluationResult;
use SineMacula\Laravel\Authorization\Events\AuthorizationFailed;
use SineMacula\Laravel\Authorization\Events\DecisionEvaluated;

/**
 * Unit tests for the two manager-dispatched decision events.
 *
 * Both events are promoted-parameter readonly value objects on the
 * SemVer-stable event API. The manager constructs them around the
 * principal, action, resource, context, and the full `EvaluationResult`,
 * and the test fixes the shape of each property so audit listeners
 * and consumer dashboards can bind against a stable surface.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DecisionEvaluated::class)]
#[CoversClass(AuthorizationFailed::class)]
final class DecisionEventsTest extends TestCase
{
    /**
     * `DecisionEvaluated` exposes every constructor argument through
     * readonly properties.
     *
     * @return void
     */
    public function testDecisionEvaluatedExposesEveryConstructorArgument(): void
    {
        $principal = new \stdClass;
        $result    = new EvaluationResult(allowed: true, reason: DecisionReason::EXPLICIT_ALLOW, trace: []);
        $context   = ['tenant' => 'org-1'];

        $event = new DecisionEvaluated(
            principal: $principal,
            action: 'posts:create',
            resource: 'arn:post:42',
            context: $context,
            result: $result,
        );

        self::assertSame($principal, $event->principal);
        self::assertSame('posts:create', $event->action);
        self::assertSame('arn:post:42', $event->resource);
        self::assertSame($context, $event->context);
        self::assertSame($result, $event->result);
    }

    /**
     * `AuthorizationFailed` exposes every constructor argument
     * through readonly properties and accepts a null principal for
     * anonymous denials.
     *
     * @return void
     */
    public function testAuthorizationFailedAcceptsNullPrincipalAndExposesArguments(): void
    {
        $result = new EvaluationResult(allowed: false, reason: DecisionReason::IMPLICIT_DENY, trace: []);

        $event = new AuthorizationFailed(
            principal: null,
            action: 'posts:delete',
            resource: null,
            context: [],
            result: $result,
        );

        self::assertNull($event->principal);
        self::assertSame('posts:delete', $event->action);
        self::assertNull($event->resource);
        self::assertSame([], $event->context);
        self::assertSame($result, $event->result);
    }
}
