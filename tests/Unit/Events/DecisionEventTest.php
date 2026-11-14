<?php

declare(strict_types = 1);

namespace Tests\Unit\Events;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\DecisionProvenance;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionEffect;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReport;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Evaluation\Enums\TraceOutcome;
use SineMacula\Laravel\Authorization\Evaluation\StatementReference;
use SineMacula\Laravel\Authorization\Evaluation\TraceEntry;
use SineMacula\Laravel\Authorization\Events\AuthorizationFailed;
use SineMacula\Laravel\Authorization\Events\DecisionEvaluated;
use SineMacula\Laravel\Authorization\Events\DecisionEvent;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Unit tests for the shape both decision events share: references, names and
 * ids, made from a decision and its provenance, never the decision itself.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(DecisionEvent::class)]
final class DecisionEventTest extends TestCase
{
    /**
     * An event exposes every constructor argument through readonly properties.
     *
     * @return void
     */
    public function testExposesEveryConstructorArgument(): void
    {
        $subject    = new Reference('user', '1');
        $identity   = new Reference('identity', '2');
        $previewer  = new Reference('user', '3');
        $tenant     = new Reference('tenant', '4');
        $statements = [new StatementReference('editors', 0, '9', 'edit')];

        $event = new DecisionEvaluated(
            $subject,
            $identity,
            $previewer,
            'posts:edit',
            'post:42',
            $tenant,
            'admin',
            DecisionEffect::DENY,
            DecisionReason::EXPLICIT_DENY,
            $statements,
            true,
            ['activation-1'],
            ['resource.status'],
        );

        self::assertSame($subject, $event->subject);
        self::assertSame($identity, $event->identity);
        self::assertSame($previewer, $event->previewer);
        self::assertSame('posts:edit', $event->action);
        self::assertSame('post:42', $event->resource);
        self::assertSame($tenant, $event->tenant);
        self::assertSame('admin', $event->application);
        self::assertSame(DecisionEffect::DENY, $event->effect);
        self::assertSame(DecisionReason::EXPLICIT_DENY, $event->reason);
        self::assertSame($statements, $event->statements);
        self::assertTrue($event->usedBreakGlass);
        self::assertSame(['activation-1'], $event->activations);
        self::assertSame(['resource.status'], $event->keys);
    }

    /**
     * An event made from a decision and its provenance carries the provenance's
     * references, the action and the resource, the decision's effect, reason
     * and deciding statements, the keys its trace tested, and no break-glass
     * grant, as the class it is made through.
     *
     * @return void
     */
    public function testIsMadeFromTheDecisionAndItsProvenance(): void
    {
        $statement = new StatementReference('editors', 1, '9', 'deny-drafts', 'post:*');
        $decision  = Decision::deny(DecisionReason::EXPLICIT_DENY, DecisionStage::DENY, [$statement], [
            new TraceEntry(DecisionStage::DENY, TraceOutcome::MATCHED, $statement, ['resource.status' => true, 'input.reason' => true]),
        ]);
        $provenance = new DecisionProvenance(new Reference('user', '1'), new Reference('identity', '2'), new Reference('user', '3'), new Reference('tenant', '4'), 'admin');

        $event = AuthorizationFailed::of($provenance, 'posts:publish', 'post:42', $decision);

        self::assertInstanceOf(AuthorizationFailed::class, $event);
        self::assertSame($provenance->subject, $event->subject);
        self::assertSame($provenance->identity, $event->identity);
        self::assertSame($provenance->previewer, $event->previewer);
        self::assertSame('posts:publish', $event->action);
        self::assertSame('post:42', $event->resource);
        self::assertSame($provenance->tenant, $event->tenant);
        self::assertSame('admin', $event->application);
        self::assertSame(DecisionEffect::DENY, $event->effect);
        self::assertSame(DecisionReason::EXPLICIT_DENY, $event->reason);
        self::assertSame([$statement], $event->statements);
        self::assertFalse($event->usedBreakGlass);
        self::assertSame([], $event->activations);
        self::assertSame(['resource.status', 'input.reason'], $event->keys);
        self::assertFalse($event->isAllowed());
    }

    /**
     * An allow made into an event names no reason and reads as allowed; a
     * decision about no subject names none.
     *
     * @return void
     */
    public function testAnAllowIsAllowed(): void
    {
        $event = DecisionEvaluated::of(new DecisionProvenance, 'posts:read', null, Decision::allow(DecisionStage::ALLOW));

        self::assertInstanceOf(DecisionEvaluated::class, $event);
        self::assertTrue($event->isAllowed());
        self::assertSame(DecisionEffect::ALLOW, $event->effect);
        self::assertNull($event->reason);
        self::assertNull($event->subject);
        self::assertNull($event->resource);
        self::assertSame([], $event->statements);
        self::assertSame([], $event->keys);
    }

    /**
     * An event made with a reason and a sensitive action reports them as they
     * were given, whatever reason its decision has.
     *
     * @return void
     */
    public function testReportsTheReasonAndSensitivityItWasMadeWith(): void
    {
        $denial = Decision::deny(DecisionReason::EXPLICIT_DENY, DecisionStage::DENY);
        $event  = DecisionEvaluated::of(new DecisionProvenance, 'posts:delete', null, $denial, DecisionReport::SENSITIVE_ACTION, true);
        $made   = self::event(DecisionEffect::ALLOW, null, null, DecisionReport::DENIAL, true);

        self::assertSame(DecisionReport::SENSITIVE_ACTION, $event->reportedBecause());
        self::assertTrue($event->isSensitiveAction());
        self::assertSame(DecisionReport::DENIAL, $made->reportedBecause());
        self::assertTrue($made->isSensitiveAction());
    }

    /**
     * An event made without a reason names the most specific one its decision
     * has, as though every setting were on, and no sensitive action: a
     * preview's, then insufficient authentication, then any denial, then any
     * allow.
     *
     * @return void
     */
    public function testAnEventMadeWithoutAReasonNamesTheMostSpecificItHas(): void
    {
        $previewer = new Reference('user', '3');

        self::assertSame(DecisionReport::PREVIEW, self::event(DecisionEffect::ALLOW, null, $previewer)->reportedBecause());
        self::assertSame(DecisionReport::PREVIEW, self::event(DecisionEffect::DENY, DecisionReason::INSUFFICIENT_AUTHENTICATION, $previewer)->reportedBecause());
        self::assertSame(DecisionReport::INSUFFICIENT_AUTHENTICATION, self::event(DecisionEffect::DENY, DecisionReason::INSUFFICIENT_AUTHENTICATION)->reportedBecause());
        self::assertSame(DecisionReport::DENIAL, self::event(DecisionEffect::DENY, DecisionReason::NO_MATCH)->reportedBecause());
        self::assertSame(DecisionReport::ALL_ALLOWS, self::event(DecisionEffect::ALLOW, null)->reportedBecause());
        self::assertFalse(self::event(DecisionEffect::ALLOW, null)->isSensitiveAction());
        self::assertFalse(DecisionEvaluated::of(new DecisionProvenance, 'posts:read', null, Decision::allow(DecisionStage::ALLOW))->isSensitiveAction());
        self::assertSame(
            DecisionReport::DENIAL,
            AuthorizationFailed::of(new DecisionProvenance, 'posts:read', null, Decision::deny(DecisionReason::NO_MATCH, DecisionStage::IMPLICIT))->reportedBecause(),
        );
    }

    /**
     * An event made from an allow that used break-glass says so and names the
     * activations behind it, and, made without a reason, names break-glass
     * before every other, a preview's included.
     *
     * @return void
     */
    public function testAnAllowThatUsedBreakGlassNamesItsActivations(): void
    {
        $decision   = Decision::allow(DecisionStage::ALLOW)->withActivations(['activation-2', 'activation-1']);
        $provenance = new DecisionProvenance(new Reference('user', '1'), null, new Reference('user', '3'));
        $event      = DecisionEvaluated::of($provenance, 'posts:read', null, $decision);
        $reported   = DecisionEvaluated::of($provenance, 'posts:read', null, $decision, DecisionReport::PREVIEW);

        self::assertTrue($event->usedBreakGlass);
        self::assertSame(['activation-1', 'activation-2'], $event->activations);
        self::assertSame(DecisionReport::BREAK_GLASS, $event->reportedBecause());
        self::assertSame(DecisionReport::PREVIEW, $reported->reportedBecause());
    }

    /**
     * Return an event on `posts:edit` with the effect, reason and previewer
     * given, made with the reason and sensitivity given.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionEffect  $effect
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason|null  $reason
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $previewer
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReport|null  $report
     * @param  bool  $isSensitive
     * @return \SineMacula\Laravel\Authorization\Events\DecisionEvaluated
     */
    private static function event(
        DecisionEffect $effect,
        ?DecisionReason $reason,
        ?Reference $previewer = null,
        ?DecisionReport $report = null,
        bool $isSensitive = false,
    ): DecisionEvaluated {
        if ($report === null) {
            return new DecisionEvaluated(null, null, $previewer, 'posts:edit', null, null, null, $effect, $reason, [], false, [], []);
        }

        return new DecisionEvaluated(null, null, $previewer, 'posts:edit', null, null, null, $effect, $reason, [], false, [], [], $report, $isSensitive);
    }
}
