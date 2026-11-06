<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Contracts\Translation\Translator;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Gate;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authorization\Concerns\DecidesThroughAuthorization;
use SineMacula\Laravel\Authorization\Events\AuthorizationFailed;
use SineMacula\Laravel\Authorization\Events\DecisionEvaluated;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Support\ResourceReference;
use Tests\Feature\Stubs\AuthenticatableIdentity;
use Tests\Feature\Stubs\DecidingLaravelPolicy;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubTenant;
use Tests\TestCase;

/**
 * Feature tests for the `DecidesThroughAuthorization` trait a Laravel policy
 * class uses to decide through the package: what its policy methods return
 * through the Gate and when called directly, for an allow, a denial, an
 * insufficient authentication and a guest, on every resource form.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversTrait(DecidesThroughAuthorization::class)]
final class DecidesThroughAuthorizationTest extends TestCase
{
    /**
     * Register the policy class for the tenant model, and fake the decision
     * events so every check is observable.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Gate::policy(StubTenant::class, DecidingLaravelPolicy::class);

        Event::fake([DecisionEvaluated::class, AuthorizationFailed::class]);
    }

    /**
     * An allowed decision is an allow through the Gate, made by exactly one
     * check of the policy method's action on the model, about the user.
     *
     * @return void
     */
    public function testAnAllowedDecisionIsAnAllow(): void
    {
        $user   = StubIdentity::create(['id' => 'user-1']);
        $tenant = StubTenant::create(['id' => 'tenant-a', 'name' => 'Tenant A']);

        $user->givePermission(Permission::create(['name' => 'tenants:publish']));

        $response = Gate::forUser($user)->inspect('publish', $tenant);

        self::assertTrue($response->allowed());
        self::assertNull($response->code());
        Event::assertDispatchedTimes(DecisionEvaluated::class, 1);
        Event::assertDispatched(
            DecisionEvaluated::class,
            static fn (DecisionEvaluated $event): bool => [$event->principal, $event->action, $event->resource] === [$user, 'tenants:publish', StubTenant::class . ':tenant-a'],
        );
        self::assertTrue(Authorization::lastDecision()?->isAllowed());
    }

    /**
     * A denial is a deny carrying the decision's reason code and, whatever the
     * reason, the generic line of the language file, never a not-found
     * response, and the trait raises nothing and reports no failure.
     *
     * @return void
     */
    public function testADenialCarriesTheTranslatedLineAndTheReasonCode(): void
    {
        $user   = StubIdentity::create(['id' => 'user-1']);
        $tenant = StubTenant::create(['id' => 'tenant-a', 'name' => 'Tenant A']);

        $unmatched = Gate::forUser($user)->inspect('publish', $tenant);

        self::assertTrue($unmatched->denied());
        self::assertSame('no_match', $unmatched->code());
        self::assertSame('This action is unauthorized.', $unmatched->message());
        self::assertNull($unmatched->status());

        $user->attachPolicy(Policy::create(['name' => 'no-publishing', 'document' => ['statements' => [['effect' => 'deny', 'actions' => ['tenants:publish']]]]]));

        $denied = Gate::forUser($user)->inspect('publish', $tenant);

        self::assertSame('explicit_deny', $denied->code());
        self::assertSame('This action is unauthorized.', $denied->message());
        Event::assertDispatchedTimes(DecisionEvaluated::class, 2);
        Event::assertNotDispatched(AuthorizationFailed::class);
    }

    /**
     * The message is the translator's generic line, in its locale, so an
     * application rewording the line rewords the denial.
     *
     * @return void
     */
    public function testTheMessageIsTheApplicationsLine(): void
    {
        $translator = $this->app?->make(Translator::class);

        self::assertInstanceOf(\Illuminate\Translation\Translator::class, $translator);

        $translator->addLines(['authorization.denied' => 'Ask an administrator.'], 'en', 'authorization');

        $response = (new DecidingLaravelPolicy)->decideFor(StubIdentity::create(['id' => 'user-1']), 'posts:read');

        self::assertSame('Ask an administrator.', $response->message());
        self::assertSame('no_match', $response->code());
    }

    /**
     * An insufficient authentication denial keeps its own code and carries the
     * generic line, and the trait raises no step-up exception.
     *
     * @return void
     */
    public function testInsufficientAuthenticationKeepsItsCode(): void
    {
        $user   = StubIdentity::create(['id' => 'user-1']);
        $tenant = StubTenant::create(['id' => 'tenant-a', 'name' => 'Tenant A']);

        $user->attachPolicy(Policy::create(['name' => 'step-up', 'document' => ['statements' => [[
            'effect'     => 'allow',
            'actions'    => ['tenants:publish'],
            'conditions' => ['authentication_requirement' => ['authentication' => ['multifactor' => []]]],
        ]]]]));

        $response = Gate::forUser($user)->inspect('publish', $tenant);

        self::assertTrue($response->denied());
        self::assertSame('insufficient_authentication', $response->code());
        self::assertSame('This action is unauthorized.', $response->message());
        Event::assertDispatchedTimes(DecisionEvaluated::class, 1);
    }

    /**
     * A guest is no subject, so it is denied as `subject_unresolved` through
     * the Gate and when called directly, without anyone being resolved in its
     * place.
     *
     * @return void
     */
    public function testAGuestIsDeniedAsSubjectUnresolved(): void
    {
        $tenant = StubTenant::create(['id' => 'tenant-a', 'name' => 'Tenant A']);

        $signedIn = AuthenticatableIdentity::create(['id' => 'signed-in']);

        $signedIn->givePermission(Permission::create(['name' => 'tenants:publish']));
        $this->actingAs($signedIn);

        $response = Gate::forUser(null)->inspect('publish', $tenant);
        $direct   = (new DecidingLaravelPolicy)->decideFor(null, 'tenants:publish', $tenant);

        foreach ([$response, $direct] as $denial) {
            self::assertTrue($denial->denied());
            self::assertSame('subject_unresolved', $denial->code());
            self::assertSame('This action is unauthorized.', $denial->message());
        }

        Event::assertDispatched(DecisionEvaluated::class, static fn (DecisionEvaluated $event): bool => $event->principal === null);
    }

    /**
     * The trait takes every resource form `check()` takes: a model, a `(type,
     * id)` pair, a reference, a model class and an opaque string, each decided
     * by its identifier, and passes the caller's context under `input`.
     *
     * @return void
     */
    public function testEveryResourceFormIsDecidedByItsIdentifier(): void
    {
        $user   = StubIdentity::create(['id' => 'user-1']);
        $tenant = StubTenant::create(['id' => 'tenant-a', 'name' => 'Tenant A']);
        $policy = new DecidingLaravelPolicy;

        $identifiers = [StubTenant::class . ':tenant-a', 'posts:7', 'comments:9', StubIdentity::class . ':*', 'arn:posts'];

        $user->attachPolicy(Policy::create(['name' => 'by-identifier', 'document' => ['statements' => [
            ['effect' => 'allow', 'actions' => ['posts:read'], 'resources' => $identifiers],
            ['effect' => 'allow', 'actions' => ['posts:edit'], 'conditions' => ['eq' => ['input.status' => 'draft']]],
        ]]]));

        foreach ([$tenant, ['posts', 7], ResourceReference::record('comments', '9'), StubIdentity::class, 'arn:posts'] as $resource) {
            self::assertTrue($policy->decideFor($user, 'posts:read', $resource)->allowed());
        }

        self::assertSame('no_match', $policy->decideFor($user, 'posts:read', 'posts:8')->code());
        self::assertTrue($policy->decideFor($user, 'posts:edit', null, ['status' => 'draft'])->allowed());
        self::assertSame('condition_failed', $policy->decideFor($user, 'posts:edit', null, ['status' => 'live'])->code());

        $resources = Event::dispatched(DecisionEvaluated::class)
            ->map(static fn (array $arguments): ?string => $arguments[0]->resource)
            ->values()
            ->all();

        self::assertSame([...$identifiers, 'posts:8', null, null], $resources);
    }
}
