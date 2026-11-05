<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authorization\Concerns\HasPolicies;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException;
use SineMacula\Laravel\Authorization\Exceptions\AuthorizationException;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature coverage for the fail-closed hydration path.
 *
 * A malformed policy row is never skipped, because skipping it would also drop
 * any deny it carries. `HasPolicies::getPolicies()` logs the row and rethrows,
 * and the authorization manager turns the failure into a denial with the
 * `invalid_policy` reason: every check for the holder denies, whatever its
 * roles, permissions or other policies would allow, until the document is
 * fixed.
 *
 * The test uses `DB::table()` to bypass the Eloquent mutator and persist a
 * malformed document directly — the mutator's validation path is the write-side
 * guardrail; this covers the read-side equivalent when a bad row reaches the
 * database by some other route (direct SQL, cross-database import, corrupted
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
     * A malformed policy row makes `getPolicies()` throw rather than silently
     * dropping the row and returning the remaining policies.
     *
     * @return void
     */
    public function testMalformedPolicyRowMakesGetPoliciesThrow(): void
    {
        $user = StubIdentity::create(['id' => (string) Str::uuid()]);

        // Persist a valid policy via the happy path.
        $user->attachPolicy(Policy::create([
            'id'       => (string) Str::uuid(),
            'name'     => 'good',
            'document' => [
                'statements' => [['effect' => 'allow', 'actions' => ['posts:create']]],
            ],
        ]));

        self::attachMalformedPolicy($user, 'bad', ['not' => 'valid-policy-shape']);

        try {
            $user->fresh()?->getPolicies();
            self::fail('getPolicies() should throw for a malformed policy row.');
        } catch (InvalidPolicyDocumentException $exception) {
            self::assertSame('bad', $exception->getPolicyName());
            self::assertSame('Invalid policy document \'bad\': Policy document has unknown keys: not.', $exception->getMessage());
        }
    }

    /**
     * Every check for the holder of a malformed policy denies with the
     * `invalid_policy` reason, even when an RBAC permission is held and another
     * valid policy explicitly allows the action.
     *
     * @return void
     */
    public function testMalformedPolicyRowDeniesEveryCheckDespiteRbacAndAllow(): void
    {
        Permission::create(['id' => (string) Str::uuid(), 'name' => 'posts:create', 'guard_name' => 'web']);
        Permission::create(['id' => (string) Str::uuid(), 'name' => 'posts:delete', 'guard_name' => 'web']);

        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        $user->givePermission('posts:create');
        $user->givePermission('posts:delete');

        $user->attachPolicy(Policy::create([
            'id'       => (string) Str::uuid(),
            'name'     => 'allow-create',
            'document' => [
                'statements' => [['effect' => 'allow', 'actions' => ['posts:create']]],
            ],
        ]));

        self::attachMalformedPolicy($user, 'corrupted', ['malformed' => true]);

        $fresh = $user->fresh();
        self::assertNotNull($fresh);

        foreach (['posts:create', 'posts:delete', 'posts:unrelated'] as $action) {
            $decision = Authorization::for($fresh)->evaluate($action);

            self::assertFalse($decision->allowed, $action);
            self::assertSame(DecisionReason::INVALID_POLICY, $decision->reason, $action);
            self::assertSame('invalid_policy', $decision->reason->value, $action);
            self::assertNull($decision->matchedStatement, $action);
            self::assertSame([], $decision->trace, $action);
            self::assertFalse(Authorization::for($fresh)->can($action), $action);
        }
    }

    /**
     * `authorize()` raises for the holder of a malformed policy even when the
     * permission is held, and the raised result carries the `invalid_policy`
     * reason.
     *
     * @return void
     */
    public function testMalformedPolicyRowMakesAuthorizeRaise(): void
    {
        Permission::create(['id' => (string) Str::uuid(), 'name' => 'posts:create', 'guard_name' => 'web']);

        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        $user->givePermission('posts:create');

        self::attachMalformedPolicy($user, 'broken', ['statements' => 'not-a-list']);

        $fresh = $user->fresh();
        self::assertNotNull($fresh);

        try {
            Authorization::for($fresh)->authorize('posts:create');
            self::fail('authorize() should raise for the holder of a malformed policy.');
        } catch (AuthorizationException) {
            $last = Authorization::lastDecision();

            self::assertNotNull($last);
            self::assertFalse($last->allowed);
            self::assertSame(DecisionReason::INVALID_POLICY, $last->reason);
        }
    }

    /**
     * Persist a malformed policy document directly and attach it to the
     * supplied identity, bypassing the write-side validation.
     *
     * @param  \Tests\Feature\Stubs\StubIdentity  $user
     * @param  string  $name
     * @param  array<string, mixed>  $document
     * @return void
     */
    private static function attachMalformedPolicy(StubIdentity $user, string $name, array $document): void
    {
        $id = (string) Str::uuid();

        DB::table('policies')->insert([
            'id'         => $id,
            'name'       => $name,
            'document'   => \json_encode($document),
            'created_at' => now(),
            'updated_at' => now(),
        ]);
        DB::table('authorizable_policies')->insert([
            'policy_id'         => $id,
            'authorizable_type' => $user->getMorphClass(),
            'authorizable_id'   => (string) $user->getKey(), // @phpstan-ignore cast.string
        ]);
    }
}
