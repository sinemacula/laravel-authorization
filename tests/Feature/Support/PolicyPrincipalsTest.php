<?php

declare(strict_types = 1);

namespace Tests\Feature\Support;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Exceptions\ResourcePolicyException;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Services\ResourcePolicyService;
use SineMacula\Laravel\Authorization\Support\PolicyPrincipals;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature tests for the rule a policy's `principals` keep about where the
 * policy is attached: every allow of a resource policy names them, and no
 * statement of a policy attached to a grantee or a role does.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(PolicyPrincipals::class)]
final class PolicyPrincipalsTest extends TestCase
{
    /** @var array<string, mixed> An allow naming its principals. */
    private const array NAMED = ['effect' => 'allow', 'actions' => ['posts:read'], 'principals' => ['user:1']];

    /** @var array<string, mixed> An allow naming none. */
    private const array UNNAMED = ['effect' => 'allow', 'actions' => ['posts:read']];

    /** @var array<string, mixed> A deny. */
    private const array DENY = ['effect' => 'deny', 'actions' => ['posts:delete']];

    /**
     * A managed policy whose allows all name principals may be attached to a
     * resource; one with an allow naming none is refused with the positions of
     * those allows, and an inline policy is refused whatever it says.
     *
     * @return void
     */
    public function testAResourcePolicyNamesThePrincipalsOfEveryAllow(): void
    {
        PolicyPrincipals::assertAttachableToResource(self::policy('named', [self::NAMED, self::DENY]));
        PolicyPrincipals::assertAttachableToResource(self::policy('denies', [self::DENY]));

        $mixed = self::policy('mixed', [self::UNNAMED, self::DENY, self::NAMED, self::UNNAMED]);

        $reason = 'every allow statement names its principals; statement #0, #3 name none.';

        self::assertRefused(static fn () => PolicyPrincipals::assertAttachableToResource($mixed), 'mixed', [0, 3], $reason);

        $inline = StubIdentity::create(['id' => 'user-1'])->createInlinePolicy('mine', ['statements' => [self::NAMED]]);

        self::assertRefused(static fn () => PolicyPrincipals::assertAttachableToResource($inline), 'mine', [], 'cannot be attached to a resource');
    }

    /**
     * A policy naming no principals may be attached to a grantee or a role; one
     * naming any is refused with the positions of the statements that name
     * them.
     *
     * @return void
     */
    public function testAGranteesPolicyNamesNoPrincipals(): void
    {
        PolicyPrincipals::assertAttachableToGrantee(self::policy('plain', [self::UNNAMED, self::DENY]));
        PolicyPrincipals::assertAttachableToGrantee(new Policy(['name' => 'empty']));

        $named = self::policy('named', [self::DENY, self::NAMED]);

        self::assertRefused(static fn () => PolicyPrincipals::assertAttachableToGrantee($named), 'named', [1], 'no statement names principals');
    }

    /**
     * A rewrite of an attached policy that breaks the rule for where it is
     * attached is refused, and the document is left as it was; one that keeps
     * it, or of a policy attached nowhere, is written.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARewriteKeepsTheRuleForWhereThePolicyIsAttached(): void
    {
        $resources = ResourcePolicyService::instance();
        $sharing   = self::policy('sharing', [self::NAMED]);
        $own       = self::policy('own', [self::UNNAMED]);
        $loose     = self::policy('loose', [self::UNNAMED]);

        self::assertNotNull($resources);

        $resources->attach($sharing, 'posts');
        StubIdentity::create(['id' => 'user-1'])->attachPolicy($own);

        self::assertRefused(static fn () => $sharing->update(['document' => ['statements' => [self::UNNAMED]]]), 'sharing', [0], 'statement #0 name none');
        self::assertRefused(static fn () => $own->update(['document' => ['statements' => [self::NAMED]]]), 'own', [0], 'statement #0 name some');
        self::assertSame([self::NAMED], self::stored($sharing));
        self::assertSame([self::UNNAMED], self::stored($own));

        $sharing->update(['document' => ['statements' => [self::DENY, self::NAMED]]]);
        $own->update(['document' => ['statements' => [self::DENY]]]);
        $loose->update(['document' => ['statements' => [self::NAMED]]]);

        self::assertSame([self::DENY, self::NAMED], self::stored($sharing));
        self::assertSame([self::NAMED], self::stored($loose));

        $own->update(['document' => ['statements' => [self::UNNAMED, self::DENY]]]);
        $loose->update(['document' => ['statements' => [self::UNNAMED]]]);

        self::assertSame([self::UNNAMED, self::DENY], self::stored($own));
        self::assertSame([self::UNNAMED], self::stored($loose));
    }

    /**
     * A policy not yet saved, or saved with its document unchanged, is checked
     * without a query.
     *
     * @return void
     */
    public function testAnUnchangedDocumentIsNotChecked(): void
    {
        $policy = self::policy('sharing', [self::UNNAMED]);

        DB::enableQueryLog();
        DB::flushQueryLog();

        PolicyPrincipals::assertRewritable($policy);
        PolicyPrincipals::assertRewritable(new Policy(['name' => 'unsaved', 'document' => ['statements' => [self::NAMED]]]));

        $policy->name = 'renamed';

        PolicyPrincipals::assertRewritable($policy);

        self::assertSame([], DB::getQueryLog());

        DB::disableQueryLog();
    }

    /**
     * Assert the call is refused for the policy, with the statements and a
     * message holding the given text.
     *
     * @param  \Closure(): mixed  $call
     * @param  string  $name
     * @param  list<int>  $statements
     * @param  string  $message
     * @return void
     */
    private static function assertRefused(\Closure $call, string $name, array $statements, string $message): void
    {
        try {
            $call();
        } catch (ResourcePolicyException $exception) {
            self::assertSame($name, $exception->getPolicyName());
            self::assertSame($statements, $exception->getStatements());
            self::assertStringContainsString($message, $exception->getMessage());

            return;
        }

        self::fail("Policy '{$name}' was not refused.");
    }

    /**
     * Return the statements of the policy as stored.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @return mixed
     */
    private static function stored(Policy $policy): mixed
    {
        return $policy->fresh()?->document['statements'] ?? null;
    }

    /**
     * Create a policy of the statements.
     *
     * @param  string  $name
     * @param  list<array<string, mixed>>  $statements
     * @return \SineMacula\Laravel\Authorization\Models\Policy
     */
    private static function policy(string $name, array $statements): Policy
    {
        return Policy::create(['name' => $name, 'document' => ['statements' => $statements]]);
    }
}
