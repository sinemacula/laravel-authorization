<?php

declare(strict_types = 1);

namespace Tests\Feature\Evaluation;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Evaluation\BreakGlassAttribution;
use SineMacula\Laravel\Authorization\Evaluation\CheckInput;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReport;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Evaluation\Enums\TraceOutcome;
use SineMacula\Laravel\Authorization\Evaluation\Policy as EvaluationPolicy;
use SineMacula\Laravel\Authorization\Evaluation\StatementReference;
use SineMacula\Laravel\Authorization\Evaluation\TraceEntry;
use SineMacula\Laravel\Authorization\Events\DecisionEvaluated;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\ResourcePolicyService;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\AuthorizationScope;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResourceReference;
use Tests\Concerns\ActivatesBreakGlass;
use Tests\Concerns\PreviewsSubjects;
use Tests\Concerns\ReadsDispatchedEvents;
use Tests\Feature\Stubs\Enums\PermissionEnum;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubMachine;
use Tests\Feature\Stubs\StubTenant;
use Tests\TestCase;

/**
 * Feature tests for the break-glass activations an allow names (N142): an
 * allowing permission, policy statement or resource policy role selector
 * carried by a role read through a live activation, directly or through its
 * ancestry, names the activation's key, on the decision and on its event, which
 * is reported whatever the settings, also on another tenant's resource; a
 * normal grant, a denial, a machine, an identity and break-glass switched off
 * name none; and the cache, warm or cold, a bulk check, a listing and a
 * preview's listing agree.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(BreakGlassAttribution::class)]
final class BreakGlassAttributionTest extends TestCase
{
    use ActivatesBreakGlass, PreviewsSubjects, ReadsDispatchedEvents;

    /** @var string The action the emergency role carries. */
    private const string ACTION = 'posts:create';

    /** @var string The action the emergency role's policy or parent allows. */
    private const string OTHER = 'posts:delete';

    /** @var string The action the resource policies allow. */
    private const string EDIT = 'posts:edit';

    /**
     * Record the decision events.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Event::fake([DecisionEvaluated::class]);
    }

    /**
     * A check allowed only through an activated role names the activation, on
     * its decision and its event, reported as break-glass with no allow
     * reported otherwise.
     *
     * @return void
     */
    public function testAnAllowThroughAnActivatedRoleNamesTheActivation(): void
    {
        $user       = StubIdentity::create(['id' => 'user-1']);
        $activation = self::activate($user, self::emergencyRole());

        [$decision, $events] = $this->checked($user, self::ACTION);

        self::assertTrue($decision->isAllowed());
        self::assertSame([$activation->id], $decision->activations);
        self::assertSame([$activation->id], Authorization::lastDecision()?->activations);
        self::assertCount(1, $events);
        self::assertTrue($events[0]->usedBreakGlass);
        self::assertSame([$activation->id], $events[0]->activations);
        self::assertSame(DecisionReport::BREAK_GLASS, $events[0]->reportedBecause());
    }

    /**
     * A permission carried by an ancestor of the activated role, and a policy
     * statement attached to it, name the activation too.
     *
     * @return void
     */
    public function testAnAncestorsPermissionAndAPolicyNameTheActivation(): void
    {
        $user   = StubIdentity::create(['id' => 'user-1']);
        $parent = Role::create(['name' => 'base']);
        $role   = Role::create(['name' => 'responder', 'parent_id' => $parent->id]);
        $other  = StubIdentity::create(['id' => 'user-2']);

        $parent->givePermission(Permission::query()->firstOrCreate(['name' => self::OTHER]));

        $inherited = self::activate($user, $role);

        [$decision, $events] = $this->checked($user, self::OTHER);

        self::assertSame([$inherited->id], $decision->activations);
        self::assertSame(DecisionReport::BREAK_GLASS, $events[0]->reportedBecause());

        $responder = self::emergencyRole(self::ACTION, 'policy-responder');
        $statement = self::activate($other, $responder);

        $responder->attachPolicy(Policy::query()->create(['name' => 'allow delete', 'document' => ['statements' => [['effect' => 'allow', 'actions' => [self::OTHER]]]]]));

        [$allowed, $reported] = $this->checked($other, self::OTHER);

        self::assertNotSame([], $allowed->statements);
        self::assertSame([$statement->id], $allowed->activations);
        self::assertTrue($reported[0]->usedBreakGlass);
        self::assertSame([$statement->id], $reported[0]->activations);
    }

    /**
     * A normal grant alone names none and is not reported; a role held both
     * ways names the activation; two activations of roles that both allow are
     * named sorted; a denial while an activation is live names none.
     *
     * @return void
     */
    public function testTheGrantsThatAllowedDecideWhatIsNamed(): void
    {
        $normal = StubIdentity::create(['id' => 'normal']);
        $both   = StubIdentity::create(['id' => 'both']);
        $two    = StubIdentity::create(['id' => 'two']);
        $role   = self::emergencyRole();

        $normal->assignRole($role);
        $both->assignRole($role);

        $held = self::activate($both, $role);
        $keys = [self::activate($two, $role)->id, self::activate($two, self::emergencyRole(self::ACTION, 'second'))->id];

        \sort($keys, \SORT_STRING);

        [$plain, $none] = $this->checked($normal, self::ACTION);
        [$twice]        = $this->checked($both, self::ACTION);
        [$sorted]       = $this->checked($two, self::ACTION);
        [$denied, $why] = $this->checked($both, self::OTHER);

        self::assertTrue($plain->isAllowed());
        self::assertSame([], $plain->activations);
        self::assertSame([], $none);
        self::assertSame([$held->id], $twice->activations);
        self::assertSame($keys, $sorted->activations);
        self::assertFalse($denied->isAllowed());
        self::assertSame([], $denied->activations);
        self::assertFalse($why[0]->usedBreakGlass);
        self::assertSame(DecisionReport::DENIAL, $why[0]->reportedBecause());
    }

    /**
     * An activated pattern covering the action names its activation beside an
     * exact permission held directly, and an activated exact permission beside
     * a pattern held directly.
     *
     * @return void
     */
    public function testAPatternThroughAnActivationNamesItBesideADirectGrant(): void
    {
        $exact   = StubIdentity::create(['id' => 'exact']);
        $pattern = StubIdentity::create(['id' => 'pattern']);

        $exact->givePermission(Permission::query()->firstOrCreate(['name' => self::ACTION]));
        $pattern->givePermission(Permission::query()->firstOrCreate(['name' => 'posts:*']));

        $wildcard = self::activate($exact, self::emergencyRole('posts:*', 'wildcard'));
        $named    = self::activate($pattern, self::emergencyRole());

        [$decision, $events] = $this->checked($exact, self::ACTION);

        self::assertSame(self::ACTION, $decision->trace[\count($decision->trace) - 1]->permission);
        self::assertSame([$wildcard->id], $decision->activations);
        self::assertSame(DecisionReport::BREAK_GLASS, $events[0]->reportedBecause());
        self::assertSame([$named->id], $this->checked($pattern, self::ACTION)[0]->activations);
    }

    /**
     * An allow on a resource of another tenant, decided at platform scope after
     * the resource's policies and guardrails were read in its own, names the
     * activation, by a policy statement or by a permission held.
     *
     * @return void
     */
    public function testAnAllowOnAnotherTenantsResourceNamesTheActivation(): void
    {
        $user   = StubIdentity::create(['id' => 'user-1']);
        $other  = StubIdentity::create(['id' => 'user-2']);
        $role   = self::emergencyRole();
        $record = static fn (): ResourceReference => ResourceReference::record('document', '7', new Reference(StubTenant::class, 'tenant-b'));

        $document = ['statements' => [['effect' => 'allow', 'actions' => [self::ACTION], 'resources' => ['*']]]];

        $role->attachPolicy(Policy::query()->create(['name' => 'allow create', 'document' => $document]));

        $statement  = self::activate($user, $role);
        $permission = self::activate($other, self::emergencyRole(self::OTHER, 'deleter'));

        [$allowed, $events] = $this->checked($user, self::ACTION, $record());
        [$held]             = $this->checked($other, self::OTHER, $record());

        self::assertTrue($allowed->isAllowed());
        self::assertNotSame([], $allowed->statements);
        self::assertSame([$statement->id], $allowed->activations);
        self::assertCount(1, $events);
        self::assertSame([$statement->id], $events[0]->activations);
        self::assertTrue($held->isAllowed());
        self::assertSame([], $held->statements);
        self::assertSame([$permission->id], $held->activations);
    }

    /**
     * A resource policy's allow whose role selector names a role held through
     * an activation, or a role above it, names the activation, a role also
     * granted included; one that also names the subject by reference, or a role
     * granted alone, names none.
     *
     * @return void
     */
    public function testAResourcePolicysRoleSelectorNamesTheActivation(): void
    {
        $user    = StubIdentity::create(['id' => 'user-1']);
        $both    = StubIdentity::create(['id' => 'user-2']);
        $granted = StubIdentity::create(['id' => 'user-3']);
        $parent  = Role::create(['name' => 'base']);
        $role    = Role::create(['name' => 'responder', 'parent_id' => $parent->id]);

        self::resourcePolicy('responders', ['role:' . $role->id], ['posts', 7]);
        self::resourcePolicy('base', ['role:' . $parent->id], ['posts', 8]);
        self::resourcePolicy('named', ['role:' . $role->id, $user->getMorphClass() . ':user-1'], ['posts', 9]);

        self::assertFalse($this->checked($user, self::EDIT, ['posts', 7])[0]->isAllowed());

        $activation = self::activate($user, $role);
        $held       = self::activate($both, $role);

        $both->assignRole($role);
        $granted->assignRole($role);

        [$decision, $events] = $this->checked($user, self::EDIT, ['posts', 7]);

        self::assertTrue($decision->isAllowed());
        self::assertSame([$activation->id], $decision->activations);
        self::assertSame(DecisionReport::BREAK_GLASS, $events[0]->reportedBecause());
        self::assertSame([$activation->id], $this->checked($user, self::EDIT, ['posts', 8])[0]->activations);
        self::assertSame([], $this->checked($user, self::EDIT, ['posts', 9])[0]->activations);
        self::assertSame([$held->id], $this->checked($both, self::EDIT, ['posts', 7])[0]->activations);
        self::assertSame([], $this->checked($granted, self::EDIT, ['posts', 7])[0]->activations);
    }

    /**
     * While break-glass is switched off, an allow by the normal grant of a role
     * also activated names nothing and is not reported.
     *
     * @return void
     */
    public function testNothingIsNamedWhileBreakGlassIsOff(): void
    {
        $user = StubIdentity::create(['id' => 'user-1']);
        $role = self::emergencyRole();

        $user->assignRole($role);
        self::activate($user, $role);
        self::switchBreakGlass(false);

        [$decision, $events] = $this->checked(StubIdentity::query()->findOrFail('user-1'), self::ACTION);

        self::assertTrue($decision->isAllowed());
        self::assertSame([], $decision->activations);
        self::assertSame([], $events);
        self::assertNull(BreakGlassAttribution::of(new Subject($user), self::ACTION));
    }

    /**
     * A machine's activation and an identity's name nothing, whatever the check
     * allowed.
     *
     * @return void
     */
    public function testAMachineAndAnIdentityNameNothing(): void
    {
        $role      = self::emergencyRole();
        $machine   = StubMachine::create(['id' => 'machine-1']);
        $identity  = StubIdentity::create(['id' => 'person-1']);
        $principal = StubIdentity::create(['id' => 'account-1']);

        $identity->assignRole($role);
        self::activate($machine, $role);
        self::activate($identity, $role);

        [$decision] = $this->checked(new Subject($principal, $identity), self::ACTION);

        self::assertTrue($decision->isAllowed());
        self::assertSame([], $decision->activations);
        self::assertSame([], $this->checked($machine, self::ACTION)[0]->activations);
        self::assertNull(BreakGlassAttribution::of(new Subject($machine), self::ACTION));
        self::assertNull(BreakGlassAttribution::of(new Subject($identity), self::ACTION));
        self::assertNotNull(BreakGlassAttribution::of(new Subject($principal), self::ACTION));
    }

    /**
     * An attribution names only what was noted on it: the permissions covering
     * its action for an allow whose last step names one, and the policies of
     * the statements, none for a statement of a policy built in code or a
     * resource policy's with no activated role; a denial, and an allow no step
     * or statement names, name none.
     *
     * @return void
     */
    public function testWhatTheDecisionNamesIsWhatWasNoted(): void
    {
        $user       = StubIdentity::create(['id' => 'user-1']);
        $role       = self::emergencyRole();
        $activation = self::activate($user, $role);
        $policy     = Policy::query()->create(['name' => 'allow delete', 'document' => ['statements' => [['effect' => 'allow', 'actions' => [self::OTHER]]]]]);
        $noted      = BreakGlassAttribution::of(new Subject($user), self::ACTION);
        $unnoted    = BreakGlassAttribution::of(new Subject($user), self::ACTION);
        $other      = BreakGlassAttribution::of(new Subject($user), self::OTHER);

        self::assertNotNull($noted);
        self::assertNotNull($unnoted);
        self::assertNotNull($other);

        $role->attachPolicy($policy);
        $user->getPermissions();
        $user->getPolicies();

        $noted->notePolicies();
        $other->notePolicies();

        self::assertSame(self::OTHER, $noted->notePermission(self::OTHER));
        self::assertNull($other->notePermission(null));

        $statement = Decision::allow(DecisionStage::ALLOW, [new StatementReference('allow delete', 0, $policy->id)]);
        $inCode    = Decision::allow(DecisionStage::ALLOW, [new StatementReference('allow delete', 0)]);
        $resource  = Decision::allow(DecisionStage::ALLOW, [new StatementReference('allow delete', 0, $policy->id, null, 'post:1')]);

        self::assertSame([$activation->id], $noted->behind(self::permissionAllow(self::ACTION), []));
        self::assertSame([$activation->id], $noted->behind($statement, []));
        self::assertSame([], $noted->behind($inCode, []));
        self::assertSame([], $noted->behind($resource, [EvaluationPolicy::fromArray(['name' => 'allow delete', 'statements' => []])->withId($policy->id)->withResource('post:1')]));
        self::assertSame([], $unnoted->behind(self::permissionAllow(self::ACTION), []));
        self::assertSame([], $unnoted->behind($statement, []));
        self::assertSame([], $other->behind(self::permissionAllow(self::OTHER), []));
        self::assertSame([], $noted->behind(Decision::allow(DecisionStage::ALLOW), []));
        self::assertSame([], $noted->behind(Decision::deny(DecisionReason::NO_MATCH, DecisionStage::IMPLICIT, [], [
            new TraceEntry(DecisionStage::ALLOW, TraceOutcome::NOT_HELD, null, [], null, self::ACTION),
        ]), []));
    }

    /**
     * A second check served from the memo, and a check in a later request
     * served from the store with no query, name the same activation, and so
     * does an explanation made on a cold cache.
     *
     * @return void
     */
    public function testAWarmCacheAndAnExplanationNameTheSameActivation(): void
    {
        $user       = StubIdentity::create(['id' => 'user-1']);
        $activation = self::activate($user, self::emergencyRole());

        Authorization::for($user)->explain(self::ACTION);

        self::assertSame([$activation->id], Authorization::lastDecision()?->activations);
        self::assertSame([$activation->id], $this->checked($user, self::ACTION)[0]->activations);
        self::assertSame([$activation->id], $this->checked($user, self::ACTION)[0]->activations);

        $this->app?->forgetInstance(ResolutionCache::class);

        $later = StubIdentity::query()->findOrFail('user-1');

        DB::enableQueryLog();
        DB::flushQueryLog();

        [$stored] = $this->checked($later, self::ACTION);

        $queries = DB::getQueryLog();

        self::assertSame([$activation->id], $stored->activations);
        self::assertSame([], $queries);
    }

    /**
     * A bulk check reports the allow that used break-glass alone; a listing
     * reports nothing; a preview's listing reports it with the activation,
     * whatever the settings.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testABulkCheckAListingAndAPreviewsListing(): void
    {
        $user       = self::target('user-1', [self::OTHER]);
        $activation = self::activate($user, self::emergencyRole());

        $bulk   = null;
        $events = self::reportedBy(static function () use ($user, &$bulk): void {
            $bulk = Authorization::for($user)->checkMany(['activated' => new CheckInput(self::ACTION), 'granted' => new CheckInput(self::OTHER)]);
        });

        self::assertSame([$activation->id], $bulk['activated']->activations ?? null);
        self::assertSame([], $bulk['granted']->activations ?? null);
        self::assertCount(1, $events);
        self::assertSame(self::ACTION, $events[0]->action);

        $listed = [];

        self::assertSame([], self::reportedBy(static function () use ($user, &$listed): void {
            $listed = Authorization::for($user)->permissionsFor(null, AuthorizationScope::current());
        }));
        self::assertContains(self::ACTION, $listed);

        $this->config()->set('authorization.events.decisions', ['denials' => false, 'insufficient_authentication' => false, 'previews' => false, 'allows' => 'none']);

        $preview   = $this->signIn(self::previewer())->previewFor($user);
        $previewed = self::reportedBy(static fn () => $preview->permissionsFor(null, AuthorizationScope::current()));

        self::assertSame([self::ACTION], \array_map(static fn (DecisionEvaluated $event): string => $event->action, $previewed));
        self::assertTrue($previewed[0]->usedBreakGlass);
        self::assertSame([$activation->id], $previewed[0]->activations);
        self::assertSame(DecisionReport::BREAK_GLASS, $previewed[0]->reportedBecause());
    }

    /**
     * Report no allow but a break-glass one, read every grant through the
     * persistent cache, and use the permissions of the enum.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        $config = $this->config();

        $config->set('authorization.cache.store', 'array');
        $config->set('authorization.permission_enums', [PermissionEnum::class]);
        $config->set('authorization.events.decisions.allows', 'none');
    }

    /**
     * Check the action for the subject, returning the decision and the decision
     * events it dispatched.
     *
     * @param  object  $subject
     * @param  string  $action
     * @param  mixed  $resource
     * @return array{\SineMacula\Laravel\Authorization\Evaluation\Decision, list<\SineMacula\Laravel\Authorization\Events\DecisionEvaluated>}
     */
    private function checked(object $subject, string $action, mixed $resource = null): array
    {
        $decision = null;
        $events   = self::reportedBy(static function () use ($subject, $action, $resource, &$decision): void {
            $decision = Authorization::for($subject)->check($action, $resource);
        });

        self::assertInstanceOf(Decision::class, $decision);

        return [$decision, $events];
    }

    /**
     * Return the decision events the work dispatched.
     *
     * @param  \Closure(): mixed  $work
     * @return list<\SineMacula\Laravel\Authorization\Events\DecisionEvaluated>
     */
    private static function reportedBy(\Closure $work): array
    {
        $before = \count(self::dispatchedEvents(DecisionEvaluated::class));

        $work();

        return \array_slice(self::dispatchedEvents(DecisionEvaluated::class), $before);
    }

    /**
     * Attach a resource policy allowing the edit to the principals given.
     *
     * @param  string  $name
     * @param  list<string>  $principals
     * @param  array{string, int}  $resource
     * @return void
     */
    private static function resourcePolicy(string $name, array $principals, array $resource): void
    {
        $policy = Policy::query()->create(['name' => $name, 'document' => ['statements' => [['effect' => 'allow', 'actions' => [self::EDIT], 'principals' => $principals]]]]);

        ResourcePolicyService::instance()?->attach($policy, $resource);
    }

    /**
     * Return an allow by the permission held of the name.
     *
     * @param  string  $permission
     * @return \SineMacula\Laravel\Authorization\Evaluation\Decision
     */
    private static function permissionAllow(string $permission): Decision
    {
        return Decision::allow(DecisionStage::ALLOW, [], [new TraceEntry(DecisionStage::ALLOW, TraceOutcome::HELD, null, [], null, $permission)]);
    }

    /**
     * Return the configuration of the application.
     *
     * @return \Illuminate\Config\Repository
     */
    private function config(): ConfigRepository
    {
        /** @var \Illuminate\Config\Repository */
        return app(ConfigRepository::class);
    }
}
