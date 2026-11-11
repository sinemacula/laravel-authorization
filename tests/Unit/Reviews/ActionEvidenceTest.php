<?php

declare(strict_types = 1);

namespace Tests\Unit\Reviews;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Evaluation\Enums\PolicyEffect;
use SineMacula\Laravel\Authorization\Reviews\ActionEvidence;
use SineMacula\Laravel\Authorization\Reviews\Enums\EvidenceKind;
use SineMacula\Laravel\Authorization\Reviews\OriginScope;

/**
 * Unit tests for what gives the action an action-filtered review of holdings
 * asks about: its versioned shape, its compact reach, and the evidence of a
 * policy whose document could not be read.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ActionEvidence::class)]
final class ActionEvidenceTest extends TestCase
{
    /**
     * A permission's evidence allows, names its guard, is complete, carries no
     * statement flags, and reaches as its scope does, its kind first.
     *
     * @return void
     */
    public function testAPermissionsEvidenceHasAVersionedShape(): void
    {
        $evidence = new ActionEvidence('posts:edit', EvidenceKind::PERMISSION, PolicyEffect::ALLOW, new OriginScope('tenant', 't1', 'admin', false), 'web');

        self::assertSame([
            'action'                => 'posts:edit',
            'evidence'              => 'permission',
            'effect'                => 'allow',
            'guard'                 => 'web',
            'complete'              => true,
            'has_deny'              => false,
            'has_conditions'        => false,
            'has_resource_patterns' => false,
            'has_requirements'      => false,
            'reach'                 => ['kind' => 'node', 'tenant' => ['type' => 'tenant', 'id' => 't1'], 'application' => 'admin', 'include_subtree' => false],
        ], $evidence->toArray());
    }

    /**
     * A policy's evidence says its effect and each flag of the statements
     * naming the action, and a platform reach is an explicit record, never an
     * empty tenant.
     *
     * @return void
     */
    public function testAPolicysEvidenceSaysWhatItsStatementsCarry(): void
    {
        $platform = new OriginScope(null, null, null, true);
        $evidence = new ActionEvidence('posts:edit', EvidenceKind::POLICY_STATEMENT, PolicyEffect::DENY, $platform, null, true, true, true, true, true);
        $shape    = $evidence->toArray();

        self::assertSame(['policy_statement', 'deny', null, true], [$shape['evidence'], $shape['effect'], $shape['guard'], $shape['complete']]);
        self::assertSame([true, true, true, true], [$shape['has_deny'], $shape['has_conditions'], $shape['has_resource_patterns'], $shape['has_requirements']]);
        self::assertSame(['kind' => 'platform', 'tenant' => null, 'application' => null, 'include_subtree' => true], $shape['reach']);
    }

    /**
     * A policy whose document could not be read is policy evidence with no
     * effect, incomplete, its route kept with its reach; its shape is read
     * without a warning, the missing effect shown as null.
     *
     * @return void
     */
    public function testAnUnreadablePolicyIsIncompleteEvidence(): void
    {
        $reach    = new OriginScope('tenant', 't1', null, true);
        $evidence = ActionEvidence::unreadable('posts:edit', $reach);

        self::assertSame([EvidenceKind::POLICY_STATEMENT, null, false, null], [$evidence->evidence, $evidence->effect, $evidence->isComplete, $evidence->guard]);
        self::assertSame($reach, $evidence->reach);
        self::assertSame([false, false, false, false], [$evidence->hasDeny, $evidence->hasConditions, $evidence->hasResourcePatterns, $evidence->hasRequirements]);

        $shape = self::shapeOf($evidence);

        self::assertSame(['kind' => 'subtree', 'tenant' => ['type' => 'tenant', 'id' => 't1'], 'application' => null, 'include_subtree' => true], $shape['reach']);
        self::assertSame([null, false], [$shape['effect'], $shape['complete']]);
    }

    /**
     * Return the evidence's shape, any warning raised reading it thrown.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\ActionEvidence  $evidence
     * @return array<string, mixed>
     */
    private static function shapeOf(ActionEvidence $evidence): array
    {
        \set_error_handler(static fn (int $level, string $message): never => throw new \ErrorException($message, 0, $level));

        try {
            return $evidence->toArray();
        } finally {
            \restore_error_handler();
        }
    }
}
