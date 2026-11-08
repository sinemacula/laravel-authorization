<?php

declare(strict_types = 1);

namespace Tests\Unit\Evaluation;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\DecisionEvidence;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Evaluation\Enums\GrantSource;
use SineMacula\Laravel\Authorization\Evaluation\EvidenceRecorder;
use SineMacula\Laravel\Authorization\Evaluation\GrantProvenance;
use SineMacula\Laravel\Authorization\Evaluation\Policy;
use SineMacula\Laravel\Authorization\Evaluation\StatementReference;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Unit tests for the evidence recorder: where each grant an explained check may
 * be allowed by came from, as noted while it was decided, and the evidence of
 * the grants that allowed it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EvidenceRecorder::class)]
final class EvidenceRecorderTest extends TestCase
{
    /**
     * A denial is evidenced by no grant, whatever was noted.
     *
     * @return void
     */
    public function testADenialHasNoGrant(): void
    {
        $recorder = new EvidenceRecorder;

        self::assertSame('posts:read', $recorder->notePermission(['posts:read', [GrantProvenance::unavailable('posts:read')]]));
        self::assertEquals(new DecisionEvidence, $recorder->evidenceFor(Decision::deny(DecisionReason::BOUNDARY, DecisionStage::BOUNDARY)));
    }

    /**
     * An allow no statement decided is evidenced by where the permission held
     * came from, and by none when none was noted.
     *
     * @return void
     */
    public function testAPermissionAllowIsEvidencedByItsGrants(): void
    {
        $recorder = new EvidenceRecorder;
        $grant    = new GrantProvenance(GrantSource::PERMISSION, 'posts:read', new Reference('user', '1'), false, [], true);

        self::assertEquals(new DecisionEvidence, $recorder->evidenceFor(Decision::allow(DecisionStage::ALLOW)));
        self::assertNull($recorder->notePermission([null, []]));
        self::assertSame('posts:read', $recorder->notePermission(['posts:read', [$grant]]));
        self::assertEquals(new DecisionEvidence([$grant]), $recorder->evidenceFor(Decision::allow(DecisionStage::ALLOW)));
    }

    /**
     * An allow statements decided is evidenced by where each statement's policy
     * came from, noted by its stored key and named by the policy; a resource
     * policy's by the resource it is attached to; and a policy noted with no
     * provenance, or never noted, as unavailable.
     *
     * @return void
     */
    public function testAStatementAllowIsEvidencedByItsPolicies(): void
    {
        $user     = StubIdentity::create(['id' => 'user-1']);
        $recorder = new EvidenceRecorder;
        $own      = Policy::fromArray(['name' => 'own', 'statements' => [['effect' => 'allow', 'actions' => ['a']]]])->withId('k1');
        $coded    = Policy::fromArray(['name' => 'coded', 'statements' => [['effect' => 'allow', 'actions' => ['a']]]]);
        $read     = new GrantProvenance(GrantSource::POLICY, 'k1', Reference::of($user), false, [], true);

        $recorder->notePolicies([$own], ['k1' => [$read]], $user);
        $recorder->notePolicies([$coded], null, $user, true);
        $recorder->notePolicies([$own], null);

        $evidence = $recorder->evidenceFor(Decision::allow(DecisionStage::ALLOW, [
            new StatementReference('own', 0, 'k1'),
            new StatementReference('coded', 0),
            new StatementReference('share', 1, 'k2', null, 'posts:7'),
            new StatementReference('unknown', 0, 'k3'),
        ]));

        self::assertEquals([
            $read->named('own[k1]'),
            GrantProvenance::unavailable('own[k1]'),
            GrantProvenance::unavailable('coded', Reference::of($user), true),
            new GrantProvenance(GrantSource::RESOURCE_POLICY, 'share[k2] on posts:7'),
            GrantProvenance::unavailable('unknown[k3]'),
        ], $evidence->grants);
    }

    /**
     * Policies are told apart by their stored key, or, built in code, by their
     * name: two built in code under different names, or two stored under one
     * name, never share their provenance.
     *
     * @return void
     */
    public function testPoliciesAreToldApartByKeyThenName(): void
    {
        $user     = StubIdentity::create(['id' => 'user-1']);
        $recorder = new EvidenceRecorder;
        $document = ['statements' => [['effect' => 'allow', 'actions' => ['a']]]];
        $first    = new GrantProvenance(GrantSource::POLICY, 'k1', Reference::of($user), false, [], true);
        $second   = new GrantProvenance(GrantSource::ROLE_POLICY, 'k2', Reference::of($user), false, ['editor'], true);

        $recorder->notePolicies([Policy::fromArray(['name' => 'a', ...$document])], null, $user);
        $recorder->notePolicies([Policy::fromArray(['name' => 'b', ...$document])], null, $user, true);
        $recorder->notePolicies([Policy::fromArray(['name' => 'same', ...$document])->withId('k1')], ['k1' => [$first]], $user);
        $recorder->notePolicies([Policy::fromArray(['name' => 'same', ...$document])->withId('k2')], ['k2' => [$second]], $user);

        $grants = static fn (StatementReference $statement): array => $recorder->evidenceFor(Decision::allow(DecisionStage::ALLOW, [$statement]))->grants;

        self::assertEquals([GrantProvenance::unavailable('a', Reference::of($user))], $grants(new StatementReference('a', 0)));
        self::assertEquals([$first->named('same[k1]')], $grants(new StatementReference('same', 0, 'k1')));
        self::assertEquals([$second->named('same[k2]')], $grants(new StatementReference('same', 0, 'k2')));
    }

    /**
     * A grantee that is no saved record is named as none.
     *
     * @return void
     */
    public function testAnUnsavedGranteeIsNamedAsNone(): void
    {
        $recorder = new EvidenceRecorder;
        $coded    = Policy::fromArray(['name' => 'coded', 'statements' => [['effect' => 'allow', 'actions' => ['a']]]]);

        $recorder->notePolicies([$coded], null, new StubIdentity(['id' => 'unsaved']));
        $recorder->notePolicies([$coded], null, new \stdClass);

        self::assertEquals(
            [GrantProvenance::unavailable('coded'), GrantProvenance::unavailable('coded')],
            $recorder->evidenceFor(Decision::allow(DecisionStage::ALLOW, [new StatementReference('coded', 0)]))->grants,
        );
    }
}
