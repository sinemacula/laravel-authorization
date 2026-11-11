<?php

declare(strict_types = 1);

namespace Tests\Unit\Reviews\Support;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Evaluation\Enums\PolicyEffect;
use SineMacula\Laravel\Authorization\Evaluation\Policy;
use SineMacula\Laravel\Authorization\Reviews\ActionEvidence;
use SineMacula\Laravel\Authorization\Reviews\Enums\EvidenceKind;
use SineMacula\Laravel\Authorization\Reviews\OriginScope;
use SineMacula\Laravel\Authorization\Reviews\Support\ActionStatements;

/**
 * Unit tests for whether a policy held by a route names an action, as the
 * policy matcher reads its statements, and what the statements naming it carry,
 * reported but never evaluated.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(ActionStatements::class)]
final class ActionStatementsTest extends TestCase
{
    /** @var string The action every case asks about. */
    private const string ACTION = 'posts:edit';

    /**
     * A policy with an allow statement naming the action allows it, policy
     * evidence reaching as given, complete, with no flag a plain statement does
     * not carry.
     *
     * @return void
     */
    public function testAnAllowStatementAllows(): void
    {
        $reach    = new OriginScope('tenant', 't1', null, true);
        $evidence = ActionStatements::evidence(self::policy([['effect' => 'allow', 'actions' => ['posts:edit']]]), self::ACTION, $reach);

        self::assertInstanceOf(ActionEvidence::class, $evidence);
        self::assertSame([self::ACTION, EvidenceKind::POLICY_STATEMENT, PolicyEffect::ALLOW, $reach, null, true], [
            $evidence->action, $evidence->evidence, $evidence->effect, $evidence->reach, $evidence->guard, $evidence->isComplete,
        ]);
        self::assertSame([false, false, false, false], [$evidence->hasDeny, $evidence->hasConditions, $evidence->hasResourcePatterns, $evidence->hasRequirements]);
    }

    /**
     * A policy whose statements naming the action only deny it is deny
     * evidence; one that also allows it allows, saying a statement denies.
     *
     * @return void
     */
    public function testADenyOnlyPolicyIsDenyEvidence(): void
    {
        $deny  = self::of([['effect' => 'deny', 'actions' => ['posts:*']], ['effect' => 'allow', 'actions' => ['posts:read']]]);
        $mixed = self::of([['effect' => 'deny', 'actions' => ['posts:edit']], ['effect' => 'allow', 'actions' => ['*']]]);

        self::assertSame([PolicyEffect::DENY, true], [$deny?->effect, $deny?->hasDeny]);
        self::assertSame([PolicyEffect::ALLOW, true], [$mixed?->effect, $mixed?->hasDeny]);
    }

    /**
     * A policy no statement of which names the action gives nothing: its
     * patterns do not cover it, case-sensitively, the action is literal, or its
     * `not_actions` leave it out; a `not_actions` that does not leave it out
     * names it.
     *
     * @return void
     */
    public function testAPolicyNotNamingTheActionGivesNothing(): void
    {
        $none = [
            [['effect' => 'allow', 'actions' => ['posts:read', 'comments:*']]],
            [['effect' => 'allow', 'actions' => ['Posts:edit', 'posts:EDIT']]],
            [['effect' => 'allow', 'not_actions' => ['posts:*']]],
        ];

        foreach ($none as $statements) {
            self::assertNull(self::of($statements));
        }

        self::assertNull(ActionStatements::evidence(self::policy([['effect' => 'allow', 'actions' => ['posts:edit']]]), 'posts:*', self::reach()));
        self::assertSame(PolicyEffect::ALLOW, self::of([['effect' => 'allow', 'not_actions' => ['comments:*']]])?->effect);
    }

    /**
     * An allow statement naming principals applies only in a policy attached to
     * a resource, never to a grantee or a role, so it gives the holder nothing.
     *
     * @return void
     */
    public function testAnAllowNamingPrincipalsGivesTheHolderNothing(): void
    {
        $principals = ['effect' => 'allow', 'actions' => ['posts:edit'], 'principals' => ['user:1']];

        self::assertNull(self::of([$principals]));
        self::assertSame(PolicyEffect::DENY, self::of([$principals, ['effect' => 'deny', 'actions' => ['posts:edit']]])?->effect);
    }

    /**
     * Conditions, resource patterns and an authentication requirement of a
     * statement naming the action are reported as present, each alone, never
     * evaluated; those of a statement not naming it are not.
     *
     * @return void
     */
    public function testWhatTheStatementsCarryIsReported(): void
    {
        $condition   = ['eq' => ['input.tenant' => 'org-1']];
        $requirement = ['authentication_requirement' => ['authentication' => ['multifactor' => []]]];
        $flags       = static function (array $statement): array {
            $other    = ['effect' => 'allow', 'actions' => ['posts:read'], 'resources' => ['post:*'], 'conditions' => ['eq' => ['input.x' => 'y']]];
            $evidence = self::of([$statement, $other]);

            return [$evidence?->hasConditions, $evidence?->hasResourcePatterns, $evidence?->hasRequirements];
        };

        self::assertSame([false, false, false], $flags(['effect' => 'allow', 'actions' => ['posts:edit']]));
        self::assertSame([true, false, false], $flags(['effect' => 'allow', 'actions' => ['posts:edit'], 'conditions' => $condition]));
        self::assertSame([false, true, false], $flags(['effect' => 'allow', 'actions' => ['posts:edit'], 'resources' => ['post:1']]));
        self::assertSame([false, true, false], $flags(['effect' => 'deny', 'actions' => ['posts:edit'], 'not_resources' => ['post:1']]));
        self::assertSame([false, false, true], $flags(['effect' => 'allow', 'actions' => ['posts:edit'], 'conditions' => $requirement]));
        self::assertSame([true, false, true], $flags(['effect' => 'allow', 'actions' => ['posts:edit'], 'conditions' => [...$requirement, ...$condition]]));
    }

    /**
     * Return what the policy of the statements gives the action every case asks
     * about, reaching the platform.
     *
     * @param  list<array<string, mixed>>  $statements
     * @return \SineMacula\Laravel\Authorization\Reviews\ActionEvidence|null
     */
    private static function of(array $statements): ?ActionEvidence
    {
        return ActionStatements::evidence(self::policy($statements), self::ACTION, self::reach());
    }

    /**
     * Return a policy of the statements.
     *
     * @param  list<array<string, mixed>>  $statements
     * @return \SineMacula\Laravel\Authorization\Evaluation\Policy
     */
    private static function policy(array $statements): Policy
    {
        return Policy::fromArray(['name' => 'reviewed', 'statements' => $statements]);
    }

    /**
     * Return the reach every case passes.
     *
     * @return \SineMacula\Laravel\Authorization\Reviews\OriginScope
     */
    private static function reach(): OriginScope
    {
        return new OriginScope(null, null, null, true);
    }
}
