<?php

declare(strict_types = 1);

namespace Tests\Unit\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;

/**
 * Unit tests for the decision-reason enum.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(DecisionReason::class)]
final class DecisionReasonTest extends TestCase
{
    /**
     * The enum defines exactly the twenty denial reasons, in declaration order,
     * the administration constraints' last: an allowed check carries no reason,
     * so there is no allow case.
     *
     * @return void
     */
    public function testExactlyTwentyCases(): void
    {
        self::assertSame(
            [
                DecisionReason::EXPLICIT_DENY,
                DecisionReason::NO_MATCH,
                DecisionReason::CONDITION_FAILED,
                DecisionReason::INVALID_POLICY,
                DecisionReason::SUBJECT_INACTIVE,
                DecisionReason::SUBJECT_UNRESOLVED,
                DecisionReason::RESOURCE_UNRESOLVED,
                DecisionReason::TENANT_SCOPE,
                DecisionReason::INSUFFICIENT_AUTHENTICATION,
                DecisionReason::GUARDRAIL,
                DecisionReason::BOUNDARY,
                DecisionReason::SESSION_POLICY,
                DecisionReason::ADMINISTRATION_SCOPE,
                DecisionReason::ADMINISTRATION_OWNER,
                DecisionReason::ADMINISTRATION_RANK_UNCOMPARABLE,
                DecisionReason::ADMINISTRATION_RANK,
                DecisionReason::ADMINISTRATION_SELF,
                DecisionReason::ADMINISTRATION_NOT_GRANTABLE,
                DecisionReason::ADMINISTRATION_UNPROVABLE,
                DecisionReason::ADMINISTRATION_IMPERSONATING,
            ],
            DecisionReason::cases(),
        );
    }

    /**
     * Every case is backed by its stable audit-log code.
     *
     * @return void
     */
    public function testBackingValues(): void
    {
        self::assertSame('explicit_deny', DecisionReason::EXPLICIT_DENY->value);
        self::assertSame('no_match', DecisionReason::NO_MATCH->value);
        self::assertSame('condition_failed', DecisionReason::CONDITION_FAILED->value);
        self::assertSame('invalid_policy', DecisionReason::INVALID_POLICY->value);
        self::assertSame('subject_inactive', DecisionReason::SUBJECT_INACTIVE->value);
        self::assertSame('subject_unresolved', DecisionReason::SUBJECT_UNRESOLVED->value);
        self::assertSame('resource_unresolved', DecisionReason::RESOURCE_UNRESOLVED->value);
        self::assertSame('tenant_scope', DecisionReason::TENANT_SCOPE->value);
        self::assertSame('insufficient_authentication', DecisionReason::INSUFFICIENT_AUTHENTICATION->value);
        self::assertSame('guardrail', DecisionReason::GUARDRAIL->value);
        self::assertSame('boundary', DecisionReason::BOUNDARY->value);
        self::assertSame('session_policy', DecisionReason::SESSION_POLICY->value);
        self::assertSame('administration.scope', DecisionReason::ADMINISTRATION_SCOPE->value);
        self::assertSame('administration.owner', DecisionReason::ADMINISTRATION_OWNER->value);
        self::assertSame('administration.rank_uncomparable', DecisionReason::ADMINISTRATION_RANK_UNCOMPARABLE->value);
        self::assertSame('administration.rank', DecisionReason::ADMINISTRATION_RANK->value);
        self::assertSame('administration.self', DecisionReason::ADMINISTRATION_SELF->value);
        self::assertSame('administration.not_grantable', DecisionReason::ADMINISTRATION_NOT_GRANTABLE->value);
        self::assertSame('administration.unprovable', DecisionReason::ADMINISTRATION_UNPROVABLE->value);
        self::assertSame('administration.impersonating', DecisionReason::ADMINISTRATION_IMPERSONATING->value);
    }

    /**
     * Every code keeps to the reason grammar: 1 to 64 characters of lower-case
     * letters, digits, `_`, `.`, `:` and `-`, starting with a letter or digit.
     *
     * @return void
     */
    public function testEveryCodeKeepsToTheGrammar(): void
    {
        foreach (DecisionReason::cases() as $case) {
            self::assertMatchesRegularExpression('/^[a-z0-9][a-z0-9_.:-]{0,63}$/', $case->value, "Case {$case->name} breaks the reason grammar.");
        }
    }

    /**
     * label() returns the exact human-readable text for every case.
     *
     * @return void
     */
    public function testLabelReturnsExactTextForEachCase(): void
    {
        self::assertSame('an applicable statement denies it', DecisionReason::EXPLICIT_DENY->label());
        self::assertSame('no statement or permission names it', DecisionReason::NO_MATCH->label());
        self::assertSame('a statement names it, but its conditions do not hold', DecisionReason::CONDITION_FAILED->label());
        self::assertSame('an applicable policy cannot be evaluated', DecisionReason::INVALID_POLICY->label());
        self::assertSame('the subject or its identity is inactive', DecisionReason::SUBJECT_INACTIVE->label());
        self::assertSame('there is no subject', DecisionReason::SUBJECT_UNRESOLVED->label());
        self::assertSame('the resource cannot be identified', DecisionReason::RESOURCE_UNRESOLVED->label());
        self::assertSame('the resource belongs to a tenant outside the scope', DecisionReason::TENANT_SCOPE->label());
        self::assertSame('a statement allows it once further authentication is met', DecisionReason::INSUFFICIENT_AUTHENTICATION->label());
        self::assertSame('a guardrail does not allow it', DecisionReason::GUARDRAIL->label());
        self::assertSame('a permission boundary does not allow it', DecisionReason::BOUNDARY->label());
        self::assertSame('a session cap does not allow it', DecisionReason::SESSION_POLICY->label());
        self::assertSame('it reaches beyond the scope the actor administers', DecisionReason::ADMINISTRATION_SCOPE->label());
        self::assertSame('it edits a record from outside the tenant that owns it', DecisionReason::ADMINISTRATION_OWNER->label());
        self::assertSame('the ranks of the actor and the target cannot be compared', DecisionReason::ADMINISTRATION_RANK_UNCOMPARABLE->label());
        self::assertSame('the target is not junior to the actor', DecisionReason::ADMINISTRATION_RANK->label());
        self::assertSame('it benefits the actor itself', DecisionReason::ADMINISTRATION_SELF->label());
        self::assertSame('it hands out what the actor neither holds nor may grant', DecisionReason::ADMINISTRATION_NOT_GRANTABLE->label());
        self::assertSame('it may widen authority in a way that cannot yet be proved permitted', DecisionReason::ADMINISTRATION_UNPROVABLE->label());
        self::assertSame('it is made while impersonating', DecisionReason::ADMINISTRATION_IMPERSONATING->label());
    }

    /**
     * label() returns a non-empty string for every case.
     *
     * @return void
     */
    public function testLabelReturnsNonEmptyStringForEachCase(): void
    {
        foreach (DecisionReason::cases() as $case) {
            self::assertNotSame('', $case->label(), "Case {$case->name} returned an empty label.");
        }
    }

    /**
     * tryFrom() resolves every known backing value.
     *
     * @return void
     */
    public function testTryFromResolvesKnownValues(): void
    {
        self::assertSame(DecisionReason::EXPLICIT_DENY, DecisionReason::tryFrom('explicit_deny'));
        self::assertSame(DecisionReason::NO_MATCH, DecisionReason::tryFrom('no_match'));
        self::assertSame(DecisionReason::CONDITION_FAILED, DecisionReason::tryFrom('condition_failed'));
        self::assertSame(DecisionReason::INVALID_POLICY, DecisionReason::tryFrom('invalid_policy'));
        self::assertSame(DecisionReason::SUBJECT_INACTIVE, DecisionReason::tryFrom('subject_inactive'));
        self::assertSame(DecisionReason::SUBJECT_UNRESOLVED, DecisionReason::tryFrom('subject_unresolved'));
        self::assertSame(DecisionReason::RESOURCE_UNRESOLVED, DecisionReason::tryFrom('resource_unresolved'));
        self::assertSame(DecisionReason::TENANT_SCOPE, DecisionReason::tryFrom('tenant_scope'));
        self::assertSame(DecisionReason::INSUFFICIENT_AUTHENTICATION, DecisionReason::tryFrom('insufficient_authentication'));
        self::assertSame(DecisionReason::GUARDRAIL, DecisionReason::tryFrom('guardrail'));
        self::assertSame(DecisionReason::BOUNDARY, DecisionReason::tryFrom('boundary'));
        self::assertSame(DecisionReason::SESSION_POLICY, DecisionReason::tryFrom('session_policy'));
        self::assertSame(DecisionReason::ADMINISTRATION_SCOPE, DecisionReason::tryFrom('administration.scope'));
        self::assertSame(DecisionReason::ADMINISTRATION_OWNER, DecisionReason::tryFrom('administration.owner'));
        self::assertSame(DecisionReason::ADMINISTRATION_RANK_UNCOMPARABLE, DecisionReason::tryFrom('administration.rank_uncomparable'));
        self::assertSame(DecisionReason::ADMINISTRATION_RANK, DecisionReason::tryFrom('administration.rank'));
        self::assertSame(DecisionReason::ADMINISTRATION_SELF, DecisionReason::tryFrom('administration.self'));
        self::assertSame(DecisionReason::ADMINISTRATION_NOT_GRANTABLE, DecisionReason::tryFrom('administration.not_grantable'));
        self::assertSame(DecisionReason::ADMINISTRATION_UNPROVABLE, DecisionReason::tryFrom('administration.unprovable'));
        self::assertSame(DecisionReason::ADMINISTRATION_IMPERSONATING, DecisionReason::tryFrom('administration.impersonating'));
    }

    /**
     * tryFrom() returns null for an unknown value, and for each code the
     * reasons used to carry, which no longer exist.
     *
     * @return void
     */
    public function testTryFromReturnsNullForUnknownValue(): void
    {
        self::assertNull(DecisionReason::tryFrom('unknown'));
        self::assertNull(DecisionReason::tryFrom('explicit_allow'));
        self::assertNull(DecisionReason::tryFrom('implicit_deny'));
        self::assertNull(DecisionReason::tryFrom('rbac_allow'));
    }
}
