<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Traits\HasPolicies;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature coverage for the fail-closed hydration path.
 *
 * `HasPolicies::getPolicies()` must not bubble a single malformed
 * row out to the request: the spec mandates deny-biased behaviour
 * — the bad row is dropped, the remaining policies continue to
 * evaluate, and an `ALLOW` statement from a broken document can
 * never win because the row was never hydrated.
 *
 * The test uses `DB::table()` to bypass the Eloquent mutator and
 * persist a malformed document directly — the mutator's
 * validation path is the write-side guardrail; this covers the
 * read-side equivalent when a bad row reaches the database by
 * some other route (direct SQL, cross-database import, corrupted
 * backup).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversTrait(HasPolicies::class)]
final class FailClosedPolicyHydrationTest extends TestCase
{
    /**
     * A malformed policy row is silently skipped and the
     * remaining policies still evaluate.
     *
     * @return void
     */
    public function testMalformedPolicyRowIsSkipped(): void
    {
        $user = StubIdentity::create(['id' => (string) Str::uuid()]);

        // Persist a valid policy via the happy path.
        $good = Policy::create([
            'id'       => (string) Str::uuid(),
            'name'     => 'good',
            'document' => [
                'statements' => [['effect' => 'allow', 'actions' => ['posts:create']]],
            ],
        ]);
        $user->attachPolicy($good);

        // Persist a malformed row by writing raw JSON that does
        // not satisfy `Policy::fromArray()`. `DB::table()`
        // bypasses the Eloquent mutator so the invalid document
        // lands in the database.
        $badId = (string) Str::uuid();
        DB::table('policies')->insert([
            'id'         => $badId,
            'name'       => 'bad',
            'document'   => \json_encode(['not' => 'valid-policy-shape']),
            'created_at' => now(),
            'updated_at' => now(),
        ]);
        DB::table('authorizable_policies')->insert([
            'policy_id'         => $badId,
            'authorizable_type' => $user->getMorphClass(),
            'authorizable_id'   => (string) $user->getKey(), // @phpstan-ignore cast.string (stub key cast to string)
        ]);

        // getPolicies() yields only the good policy — no
        // InvalidPolicyDocumentException bubbles up.
        $hydrated = $user->fresh()?->getPolicies() ?? [];

        self::assertCount(1, $hydrated);
        self::assertSame('good', $hydrated[0]->name);
    }

    /**
     * A full authorization check still produces a decision when
     * a malformed row is attached — the engine stays deny-biased
     * by excluding the bad row from the evaluation set.
     *
     * @return void
     */
    public function testAuthorizationStillEvaluatesAroundMalformedRow(): void
    {
        $user = StubIdentity::create(['id' => (string) Str::uuid()]);

        $user->attachPolicy(Policy::create([
            'id'       => (string) Str::uuid(),
            'name'     => 'allow-create',
            'document' => [
                'statements' => [['effect' => 'allow', 'actions' => ['posts:create']]],
            ],
        ]));

        $badId = (string) Str::uuid();
        DB::table('policies')->insert([
            'id'         => $badId,
            'name'       => 'corrupted',
            'document'   => \json_encode(['malformed' => true]),
            'created_at' => now(),
            'updated_at' => now(),
        ]);
        DB::table('authorizable_policies')->insert([
            'policy_id'         => $badId,
            'authorizable_type' => $user->getMorphClass(),
            'authorizable_id'   => (string) $user->getKey(), // @phpstan-ignore cast.string (stub key cast to string)
        ]);

        $decision = Authorization::for($user->fresh())->evaluate('posts:create');

        self::assertTrue($decision->allowed);
        self::assertSame(DecisionReason::EXPLICIT_ALLOW, $decision->reason);
    }
}
