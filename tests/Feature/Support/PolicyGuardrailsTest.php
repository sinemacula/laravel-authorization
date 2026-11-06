<?php

declare(strict_types = 1);

namespace Tests\Feature\Support;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Exceptions\GuardrailException;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Support\PolicyGuardrails;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\TestCase;

/**
 * Feature tests for the rule a policy in use as a guardrail keeps: it is
 * neither edited nor deleted until every guardrail it is has been removed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(PolicyGuardrails::class)]
final class PolicyGuardrailsTest extends TestCase
{
    /**
     * A policy that is no guardrail is edited and deleted freely, and one not
     * yet saved passes without a query.
     *
     * @return void
     */
    public function testAPolicyThatIsNoGuardrailPasses(): void
    {
        $policy = self::policy('free');
        $other  = self::policy('rail');

        self::set($other, null);

        PolicyGuardrails::assertEditable($policy);
        PolicyGuardrails::assertDeletable($policy);

        DB::enableQueryLog();
        DB::flushQueryLog();

        PolicyGuardrails::assertEditable(new Policy(['name' => 'unsaved']));
        PolicyGuardrails::assertDeletable(new Policy(['name' => 'unsaved']));

        self::assertSame([], DB::getQueryLog());

        DB::disableQueryLog();
    }

    /**
     * Editing and deleting a guardrail's policy are each refused, naming the
     * policy, the change, and every scope it caps, the platform first and then
     * each tenant in order.
     *
     * @return void
     */
    public function testEditingAndDeletingAGuardrailsPolicyAreRefused(): void
    {
        $policy = self::policy('rail');

        self::set($policy, new Reference('stub_tenant', 'tenant-b'));
        self::set($policy, new Reference('stub_tenant', 'tenant-a'));
        self::set($policy, null);

        $scopes = [null, new Reference('stub_tenant', 'tenant-a'), new Reference('stub_tenant', 'tenant-b')];

        foreach (['editing' => PolicyGuardrails::assertEditable(...), 'deleting' => PolicyGuardrails::assertDeletable(...)] as $change => $assert) {
            try {
                $assert($policy);
                self::fail("The {$change} was not refused.");
            } catch (GuardrailException $exception) {
                self::assertSame(GuardrailException::IN_USE, $exception->getReason());
                self::assertSame('rail', $exception->getPolicyName());
                self::assertEquals($scopes, $exception->getTenants());
                self::assertStringContainsString('is a guardrail on the platform, stub_tenant:tenant-a, stub_tenant:tenant-b; ', $exception->getMessage());
                self::assertStringEndsWith("remove each guardrail through the guardrail service before {$change} the policy.", $exception->getMessage());
            }
        }
    }

    /**
     * Once every guardrail the policy is has been removed, it is edited and
     * deleted again.
     *
     * @return void
     */
    public function testAPolicyNoLongerAGuardrailPassesAgain(): void
    {
        $policy = self::policy('rail');

        self::set($policy, new Reference('stub_tenant', 'tenant-a'));

        DB::table('guardrails')->where('policy_id', $policy->id)->delete();

        PolicyGuardrails::assertEditable($policy);
        PolicyGuardrails::assertDeletable($policy);

        self::assertTrue($policy->delete());
    }

    /**
     * Create a policy allowing `posts:read`.
     *
     * @param  string  $name
     * @return \SineMacula\Laravel\Authorization\Models\Policy
     */
    private static function policy(string $name): Policy
    {
        return Policy::create(['name' => $name, 'document' => ['statements' => [['effect' => 'allow', 'actions' => ['posts:read']]]]]);
    }

    /**
     * Set the policy as a guardrail on the tenant or the platform, past the
     * guardrail service.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @return void
     */
    private static function set(Policy $policy, ?Reference $tenant): void
    {
        DB::table('guardrails')->insert(['policy_id' => $policy->id, 'tenant_type' => $tenant?->type, 'tenant_id' => $tenant?->id]);
    }
}
