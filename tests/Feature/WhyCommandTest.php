<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authorization\Console\WhyCommand;
use SineMacula\Laravel\Authorization\Context\CheckContextFactory;
use SineMacula\Laravel\Authorization\Contracts\ConsoleSubjectResolver;
use SineMacula\Laravel\Authorization\Contracts\ResourceTenantResolver;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Events\DecisionEvaluated;
use SineMacula\Laravel\Authorization\Exceptions\UnresolvedSubjectException;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Services\ResourcePolicyService;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\AuthorizationScope;
use SineMacula\Laravel\Authorization\Support\Reference;
use Symfony\Component\Console\Input\ArgvInput;
use Symfony\Component\Console\Output\BufferedOutput;
use Symfony\Component\Console\Tester\CommandTester;
use Tests\Concerns\ActsAsTenant;
use Tests\Feature\Stubs\FailingContextSource;
use Tests\Feature\Stubs\FailingSubjectResolver;
use Tests\Feature\Stubs\FixedConsoleSubjectResolver;
use Tests\Feature\Stubs\FixedResourceTenantResolver;
use Tests\Feature\Stubs\NumberedIdentity;
use Tests\Feature\Stubs\PrincipalSubjectResolver;
use Tests\Feature\Stubs\RecordingResourceAttributes;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubSecondIdentity;
use Tests\Feature\Stubs\StubTenant;
use Tests\TestCase;

/**
 * Feature tests for the `authorization:why` Artisan command (AUTHZ-11.5, N90,
 * N91): the explanation of a saved subject's check, in the scope its options
 * name and never the one in place, with `--context` as the `input` namespace
 * alone, printed once as text or as its versioned JSON, exiting 0 for any
 * explanation, 2 for an invalid invocation and 1 for a failure, and never
 * printing a value.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(WhyCommand::class)]
final class WhyCommandTest extends TestCase
{
    use ActsAsTenant;

    /** @var string A value the command is given, which nothing it prints may carry. */
    private const string SECRET = 'sentinel-context-7f3a';

    /** @var string A model attribute, which nothing the command prints may carry. */
    private const string NAME = 'sentinel-name-91b2';

    /** @var string A resource attribute a provider supplies, which nothing the command prints may carry. */
    private const string STATUS = 'sentinel-status-4e7d';

    /** @var string The refusal of a resource with a colon but an empty type or key. */
    private const string RESOURCE = 'The resource must be in the format {morphType}:{key} or {morphType}:* (e.g. post:42), or be given with --opaque.';

    /**
     * The command is registered under its `NAME` constant, the name its
     * signature declares.
     *
     * @return void
     */
    public function testTheCommandsNameIsItsConstant(): void
    {
        self::assertSame('authorization:why', WhyCommand::NAME);
        self::assertInstanceOf(WhyCommand::class, Artisan::all()[WhyCommand::NAME] ?? null);
        self::assertSame(WhyCommand::NAME, Artisan::all()[WhyCommand::NAME]->getName());
    }

    /**
     * An allowed check is explained as text after the preamble and exits 0.
     *
     * @return void
     */
    public function testExplainsAnAllowAsText(): void
    {
        $user = $this->editor('user-1');

        [$code, $output] = self::why(['subject' => StubIdentity::class . ':user-1', 'action' => 'posts:edit']);

        self::assertSame(0, $code);
        self::assertStringStartsWith(WhyCommand::PREAMBLE . "\n\nALLOW at the allow stage by permission \"posts:edit\".\n", $output);
        self::assertStringContainsString('  grant role permission "posts:edit" to principal ' . self::escaped($user) . ' through role "editor" in platform', $output);
        $about = self::escaped($user);

        self::assertStringContainsString("  request \"posts:edit\" about {$about} (identity {$about}); asked in platform, decided in platform", $output);
    }

    /**
     * A denied check is explained as text too, and still exits 0.
     *
     * @return void
     */
    public function testExplainsADenyAsText(): void
    {
        StubIdentity::create(['id' => 'user-2']);

        [$code, $output] = self::why(['subject' => StubIdentity::class . ':user-2', 'action' => 'posts:delete']);

        self::assertSame(0, $code);
        self::assertStringContainsString("\n\nDENY (no_match: ", $output);
        self::assertStringContainsString(' at the implicit stage', $output);
    }

    /**
     * With `--format=json`, an allow and a deny each print the explanation's
     * versioned JSON alone, with no preamble or styling, and exit 0.
     *
     * @return void
     */
    public function testJsonPrintsOnlyTheVersionedDocument(): void
    {
        $user = $this->editor('user-3');

        foreach (['posts:edit' => 'allow', 'posts:delete' => 'deny'] as $action => $effect) {
            [$code, $output] = self::why(['subject' => StubIdentity::class . ':user-3', 'action' => $action, '--format' => 'json']);

            self::assertSame(0, $code, $action);
            self::assertStringStartsWith('{', $output, $action);
            self::assertSame('}', \trim($output)[-1], $action);
            self::assertStringNotContainsString("\e", $output, $action);
            self::assertStringNotContainsString('Explanation for', $output, $action);

            $document = self::decoded($output);

            self::assertSame(1, $document['version'], $action);
            self::assertSame($effect, $document['effect'], $action);
            self::assertSame('recorded', $document['evidence'], $action);
            self::assertSame(['type' => $user->getMorphClass(), 'id' => 'user-3'], $document['request']['subject'] ?? null, $action);
        }
    }

    /**
     * The JSON is the explanation `explain()` makes of the same check, under
     * the same scope and input, rendered once, pretty-printed with its slashes
     * unescaped, and written as it is, so markup in a name stays in the JSON
     * rather than styling the terminal.
     *
     * @return void
     */
    public function testJsonIsTheExplanationOfTheSameCheck(): void
    {
        $user     = $this->editor('user-4');
        $resource = '<fg=red>posts/42</>';

        [, $output] = self::why(['subject' => StubIdentity::class . ':user-4', 'action' => 'posts:edit', 'resource' => $resource, '--format' => 'json']);

        $explanation = Authorization::for(AuthorizationScope::platform()->subjectIn(new Subject($user, $user, guard: 'web')))->explain('posts:edit', $resource);

        self::assertSame(\json_encode($explanation, \JSON_PRETTY_PRINT | \JSON_UNESCAPED_SLASHES | \JSON_THROW_ON_ERROR) . "\n", $output);
        self::assertSame($resource, self::decoded($output)['request']['resource'] ?? null);
    }

    /**
     * The verdict is the one `check()` gives the same subject, under the same
     * scope and input, allowed and denied alike.
     *
     * @return void
     */
    public function testTheVerdictIsTheChecksVerdict(): void
    {
        $user = StubIdentity::create(['id' => 'user-5']);
        $user->attachPolicy(self::policy('purposes', [['effect' => 'allow', 'actions' => ['posts:read'], 'conditions' => ['eq' => ['input.purpose' => 'support']]]]));

        foreach (['support' => 'allow', 'sales' => 'deny'] as $purpose => $effect) {
            $context         = '{"purpose":"' . $purpose . '"}';
            [$code, $output] = self::why(['subject' => StubIdentity::class . ':user-5', 'action' => 'posts:read', '--context' => $context, '--format' => 'json']);

            $input   = ['purpose' => $purpose];
            $scope   = AuthorizationScope::platform();
            $checked = $scope->within(static fn (): bool => Authorization::for($scope->subjectIn(new Subject($user, $user)))->check('posts:read', null, $input)->isAllowed());

            self::assertSame(0, $code, $context);
            self::assertSame($effect, self::decoded($output)['effect'], $context);
            self::assertSame($effect === 'allow', $checked, $context);
        }
    }

    /**
     * `--context` fills the `input` namespace: without it the key is missing,
     * reported as found missing and nothing more.
     *
     * @return void
     */
    public function testTheContextIsTheInputNamespace(): void
    {
        $user = StubIdentity::create(['id' => 'user-6']);
        $user->attachPolicy(self::policy('purposes', [['effect' => 'allow', 'actions' => ['posts:read'], 'conditions' => ['eq' => ['input.purpose' => 'support']]]]));

        [, $without] = self::why(['subject' => StubIdentity::class . ':user-6', 'action' => 'posts:read', '--format' => 'json']);
        [, $with]    = self::why(['subject' => StubIdentity::class . ':user-6', 'action' => 'posts:read', '--format' => 'json', '--context' => '{"purpose":"support"}']);

        self::assertSame('deny', self::decoded($without)['effect']);
        self::assertSame(['input.purpose'], self::decoded($without)['missing_keys']);
        self::assertSame('allow', self::decoded($with)['effect']);
        self::assertSame([], self::decoded($with)['missing_keys']);
    }

    /**
     * Neither the context's values, the policies' operands, the subject's model
     * attributes, a session the resolver gave nor any resource attribute
     * appears in the output, as text or as JSON.
     *
     * @return void
     */
    public function testNoValueIsEverPrinted(): void
    {
        $principal = StubIdentity::create(['id' => 'principal-1', 'name' => self::NAME]);
        $person    = StubSecondIdentity::create(['id' => 'person-1', 'name' => self::NAME]);
        $posts     = new RecordingResourceAttributes;

        $principal->attachPolicy(self::policy('secrets', [
            ['effect' => 'allow', 'actions' => ['posts:read'], 'conditions' => ['eq' => ['input.code' => self::SECRET]]],
            ['effect' => 'deny', 'actions' => ['posts:read'], 'conditions' => ['eq_if_exists' => ['resource.status' => 'classified']]],
        ]));

        $this->app?->instance(SubjectResolver::class, new PrincipalSubjectResolver($principal, $person));
        $this->useResourceAttributes('post', $posts);

        $context = '{"code":"' . self::SECRET . '","note":"' . self::SECRET . '"}';
        $subject = StubSecondIdentity::class . ':person-1';

        foreach (['text', 'json'] as $format) {
            [$code, $output] = self::why(['subject' => $subject, 'action' => 'posts:read', 'resource' => 'post:42', '--context' => $context, '--format' => $format]);

            self::assertSame(0, $code, $format);

            foreach ([self::SECRET, self::NAME, PrincipalSubjectResolver::SESSION, 'owner@example.com', 'classified', 'draft'] as $value) {
                self::assertStringNotContainsString($value, $output, $format);
            }
        }

        self::assertCount(2, $posts->calls);
    }

    /**
     * A record's attributes come only from its type's attribute provider: the
     * row is never loaded, so a model column the provider does not supply stays
     * missing, and is reported so, while the key the provider supplies holds.
     *
     * @return void
     */
    public function testResourceAttributesComeOnlyFromProviders(): void
    {
        $user  = StubIdentity::create(['id' => 'user-7', 'name' => self::NAME]);
        $posts = new RecordingResourceAttributes;

        $conditions = ['eq' => ['resource.status' => 'draft', 'resource.name' => self::NAME]];

        $user->attachPolicy(self::policy('drafts', [['effect' => 'allow', 'actions' => ['posts:edit'], 'conditions' => $conditions]]));
        $this->useResourceAttributes($user->getMorphClass(), $posts);

        [$code, $output] = self::why(['subject' => StubIdentity::class . ':user-7', 'action' => 'posts:edit', 'resource' => StubIdentity::class . ':user-7', '--format' => 'json']);

        $document = self::decoded($output);

        self::assertSame(0, $code);
        self::assertSame('deny', $document['effect']);
        self::assertSame(['resource.name'], $document['missing_keys']);
        self::assertSame(StubIdentity::class . ':user-7', $document['request']['resource'] ?? null);
        self::assertEquals(['resource.status' => 'held', 'resource.name' => 'missing'], self::outcomes($document));
        self::assertCount(1, $posts->calls);
        self::assertSame(StubIdentity::class . ':user-7', $posts->calls[0][0]->identifier);
        self::assertNull($posts->calls[0][1]);
        self::assertStringNotContainsString(self::NAME, $output);
    }

    /**
     * A `{morphType}:{key}` resource names that record, as the `(type, id)`
     * pair `check()` takes: the resource policy attached to it decides, the
     * condition on the attribute its provider supplies holds, and neither the
     * provider's values nor the policy's operands are printed.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testExplainsARecordWithItsPolicyAndProviderAttribute(): void
    {
        $user  = StubIdentity::create(['id' => 'user-18']);
        $posts = new RecordingResourceAttributes(self::STATUS);

        self::attach(self::policy('sharing', [self::share($user, 'posts:read', ['eq' => ['resource.status' => self::STATUS]])]), ['post', '42']);
        $this->useResourceAttributes('post', $posts);

        [$code, $json] = self::why(['subject' => StubIdentity::class . ':user-18', 'action' => 'posts:read', 'resource' => 'post:42', '--format' => 'json']);
        [, $text]      = self::why(['subject' => StubIdentity::class . ':user-18', 'action' => 'posts:read', 'resource' => 'post:42']);

        $document = self::decoded($json);
        $decided  = $document['decided_by']['statements'][0] ?? [];

        self::assertSame(0, $code);
        self::assertSame('allow', $document['effect']);
        self::assertSame('post:42', $document['request']['resource'] ?? null);
        self::assertSame(['sharing', 'share', 'post:42'], [$decided['policy'] ?? null, $decided['sid'] ?? null, $decided['resource'] ?? null]);
        self::assertSame(['resource.status' => 'held'], self::outcomes($document));
        self::assertStringContainsString('sid="share" on "post:42"', $text);
        self::assertSame(['post:42', 'post:42'], \array_map(static fn (array $call): string => $call[0]->identifier, $posts->calls));

        foreach ([$json, $text] as $output) {
            foreach ([self::STATUS, 'owner@example.com', 'classified'] as $value) {
                self::assertStringNotContainsString($value, $output);
            }
        }
    }

    /**
     * The verdict on a record is the one `check()` gives the same `(type, id)`
     * pair, under the same scope, allowed and denied alike.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheVerdictOnARecordIsTheChecksVerdict(): void
    {
        $named = StubIdentity::create(['id' => 'user-19']);
        $other = StubIdentity::create(['id' => 'user-20']);

        self::attach(self::policy('sharing', [self::share($named, 'posts:read')]), ['post', '43']);

        foreach (['user-19' => [$named, 'allow'], 'user-20' => [$other, 'deny']] as $id => [$user, $effect]) {
            [, $output] = self::why(['subject' => StubIdentity::class . ':' . $id, 'action' => 'posts:read', 'resource' => 'post:43', '--format' => 'json']);

            $scope   = AuthorizationScope::platform();
            $checked = $scope->within(static fn (): bool => Authorization::for($scope->subjectIn(new Subject($user, $user)))->check('posts:read', ['post', '43'])->isAllowed());

            self::assertSame($effect, self::decoded($output)['effect'], $id);
            self::assertSame($effect === 'allow', $checked, $id);
        }
    }

    /**
     * A record is decided with the tenant the bound resource tenant resolver
     * gives it: in the tenant named when it is that tenant's, denied as out of
     * scope when it is another's, as `check()` decides it; an opaque resource
     * has no tenant, so the resolver is never asked about it.
     *
     * @return void
     */
    public function testTheRecordsTenantApplies(): void
    {
        $tenant = self::createTenant('tenant-f');
        $other  = self::createTenant('tenant-g');
        $user   = StubIdentity::create(['id' => 'user-21']);
        $option = $tenant->getMorphClass() . ':tenant-f';

        $user->givePermission(Permission::create(['name' => 'posts:read']), null, $tenant);

        $this->app?->instance(ResourceTenantResolver::class, new FixedResourceTenantResolver(null, Reference::of($tenant)));

        [, $own] = self::why(['subject' => StubIdentity::class . ':user-21', 'action' => 'posts:read', 'resource' => 'post:44', '--tenant' => $option, '--format' => 'json']);

        $foreign = new FixedResourceTenantResolver(null, Reference::of($other));

        $this->app?->instance(ResourceTenantResolver::class, $foreign);

        $parameters  = ['subject' => StubIdentity::class . ':user-21', 'action' => 'posts:read', 'resource' => 'post:44', '--tenant' => $option, '--format' => 'json'];
        [, $outside] = self::why($parameters);
        [, $opaque]  = self::why([...$parameters, '--opaque' => true]);

        $scope   = AuthorizationScope::tenant($tenant);
        $checked = $scope->within(static fn (): ?DecisionReason => Authorization::for($scope->subjectIn(new Subject($user, $user)))->check('posts:read', ['post', '44'])->reason);

        self::assertSame('allow', self::decoded($own)['effect']);
        self::assertSame(['deny', 'tenant_scope'], [self::decoded($outside)['effect'], self::decoded($outside)['reason']]);
        self::assertSame(DecisionReason::TENANT_SCOPE, $checked);
        self::assertSame('allow', self::decoded($opaque)['effect']);
        self::assertSame([['post', '44'], ['post', '44']], $foreign->askedRecords);
    }

    /**
     * A `{morphType}:*` resource names the type alone: a policy attached to the
     * type applies, and no attribute provider is asked about a record.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testExplainsTheTypeAlone(): void
    {
        $user  = StubIdentity::create(['id' => 'user-22']);
        $posts = new RecordingResourceAttributes;

        self::attach(self::policy('creators', [self::share($user, 'posts:create')]), 'post');
        $this->useResourceAttributes('post', $posts);

        [$code, $output] = self::why(['subject' => StubIdentity::class . ':user-22', 'action' => 'posts:create', 'resource' => 'post:*', '--format' => 'json']);

        self::assertSame(0, $code);
        self::assertSame('allow', self::decoded($output)['effect']);
        self::assertSame('post:*', self::decoded($output)['request']['resource'] ?? null);
        self::assertSame('creators', self::decoded($output)['decided_by']['statements'][0]['policy'] ?? null);
        self::assertSame([], $posts->calls);
    }

    /**
     * A resource with no colon, and one with a colon given with `--opaque`, is
     * an opaque identifier: no resource policy is read for it and no attribute
     * provider is asked about it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnOpaqueResourceNamesNoRecord(): void
    {
        $user  = StubIdentity::create(['id' => 'user-23']);
        $posts = new RecordingResourceAttributes;

        self::attach(self::policy('sharing', [self::share($user, 'posts:read')]), ['post', '45']);
        $this->useResourceAttributes('post', $posts);

        foreach ([['post:45', true], ['post-45', false]] as [$resource, $isOpaque]) {
            $options         = $isOpaque ? ['--opaque' => true] : [];
            [$code, $output] = self::why(['subject' => StubIdentity::class . ':user-23', 'action' => 'posts:read', 'resource' => $resource, '--format' => 'json', ...$options]);

            self::assertSame(0, $code, $resource);
            self::assertSame('deny', self::decoded($output)['effect'], $resource);
            self::assertSame($resource, self::decoded($output)['request']['resource'] ?? null, $resource);
        }

        self::assertSame([], $posts->calls);
    }

    /**
     * Omitting the resource explains a check without one, never one about every
     * resource.
     *
     * @return void
     */
    public function testNoResourceIsACheckWithoutOne(): void
    {
        $this->editor('user-8');

        [, $output] = self::why(['subject' => StubIdentity::class . ':user-8', 'action' => 'posts:edit', '--format' => 'json']);

        $request = self::decoded($output)['request'];

        self::assertIsArray($request);
        self::assertArrayHasKey('resource', $request);
        self::assertNull(self::decoded($output)['request']['resource']);
    }

    /**
     * The scope defaults to the platform and no application; a tenant and an
     * application named isolate the grants made there from the platform's,
     * another tenant's and those for another application.
     *
     * @return void
     */
    public function testTheTenantAndApplicationIsolateGrants(): void
    {
        $tenant = self::createTenant('tenant-a');
        $other  = self::createTenant('tenant-b');
        $user   = StubIdentity::create(['id' => 'user-9']);

        $user->givePermission(Permission::create(['name' => 'posts:read']), null, $tenant, true, 'web');

        $cases = [
            'deny'  => [[], [$other->getMorphClass() . ':tenant-b', 'web'], [$tenant->getMorphClass() . ':tenant-a', null], [$tenant->getMorphClass() . ':tenant-a', 'api']],
            'allow' => [[$tenant->getMorphClass() . ':tenant-a', 'web']],
        ];

        foreach ($cases as $effect => $scopes) {
            foreach ($scopes as $scope) {
                $options = ($scope[0] ?? null) === null ? [] : ['--tenant' => $scope[0]];
                $options = ($scope[1] ?? null) === null ? $options : [...$options, '--application' => $scope[1]];

                [$code, $output] = self::why(['subject' => StubIdentity::class . ':user-9', 'action' => 'posts:read', '--format' => 'json', ...$options]);

                self::assertSame(0, $code, (string) \json_encode($scope));
                self::assertSame($effect, self::decoded($output)['effect'], (string) \json_encode($scope));
            }
        }

        [, $platform] = self::why(['subject' => StubIdentity::class . ':user-9', 'action' => 'posts:read', '--format' => 'json']);

        self::assertSame(['tenant' => null, 'application' => null], self::decoded($platform)['request']['decision_scope'] ?? null);
    }

    /**
     * The tenant in place, the request's, is never inherited: with no tenant
     * named the check is the platform's, and the tenant in place is back
     * afterwards.
     *
     * @return void
     */
    public function testTheTenantInPlaceIsNotInherited(): void
    {
        $tenant = self::createTenant('tenant-c');
        $user   = StubIdentity::create(['id' => 'user-10']);

        $user->givePermission(Permission::create(['name' => 'posts:read']), null, $tenant);

        $this->actAsTenant($tenant);

        self::assertTrue(Authorization::for($user)->check('posts:read')->isAllowed());

        [$code, $output] = self::why(['subject' => StubIdentity::class . ':user-10', 'action' => 'posts:read', '--format' => 'json']);

        self::assertSame(0, $code);
        self::assertSame('deny', self::decoded($output)['effect']);
        self::assertSame(['tenant' => null, 'application' => null], self::decoded($output)['request']['decision_scope'] ?? null);
        self::assertSame([$tenant->getMorphClass(), 'tenant-c'], TenantScope::currentTenant());

        $tenantOption = $tenant->getMorphClass() . ':tenant-c';
        [, $named]    = self::why(['subject' => StubIdentity::class . ':user-10', 'action' => 'posts:read', '--format' => 'json', '--tenant' => $tenantOption]);

        self::assertSame('allow', self::decoded($named)['effect']);
    }

    /**
     * A check that throws exits 1, printing no explanation and no value from
     * the failure, and the tenant in place is back afterwards.
     *
     * @return void
     */
    public function testAFailureExitsOneAndRestoresTheScope(): void
    {
        $tenant = self::createTenant('tenant-d');
        $user   = StubIdentity::create(['id' => 'user-11']);

        $user->attachPolicy(self::policy('ledger', [['effect' => 'allow', 'actions' => ['posts:read'], 'conditions' => ['eq' => ['ledger.balance' => 1]]]]));

        $this->app?->make(ConfigRepository::class)->set('authorization.context.sources', [FailingContextSource::class]);
        $this->app?->forgetInstance(CheckContextFactory::class);
        $this->app?->forgetInstance('authorization');
        $this->actAsTenant($tenant);

        [$code, $output] = self::why(['subject' => StubIdentity::class . ':user-11', 'action' => 'posts:read', '--tenant' => $tenant->getMorphClass() . ':tenant-d']);

        self::assertSame(1, $code);
        self::assertSame("The explanation could not be produced (RuntimeException).\n", $output);
        self::assertStringNotContainsString('4711', $output);
        self::assertSame([$tenant->getMorphClass(), 'tenant-d'], TenantScope::currentTenant());
        self::assertFalse(TenantScope::isBelowTenant());
    }

    /**
     * The decision is recorded as the last decision and reported once, as an
     * explained check is.
     *
     * @return void
     */
    public function testTheDecisionIsRecordedAndReported(): void
    {
        Event::fake([DecisionEvaluated::class]);

        $user = $this->editor('user-12');

        self::assertSame(0, self::why(['subject' => StubIdentity::class . ':user-12', 'action' => 'posts:edit'])[0]);

        $reported = Event::dispatched(DecisionEvaluated::class);

        self::assertCount(1, $reported);
        self::assertInstanceOf(DecisionEvaluated::class, $reported[0][0] ?? null);
        self::assertEquals(Reference::of($user), $reported[0][0]->subject);
        self::assertSame('posts:edit', $reported[0][0]->action);
        self::assertTrue($reported[0][0]->isAllowed());
        self::assertTrue(Authorization::lastDecision()?->hasEvidence());
    }

    /**
     * Under a subject resolver with principals, the person named is explained
     * as the principal it acts as, its identity's grants counting.
     *
     * @return void
     */
    public function testExplainsThePrincipalAPersonActsAs(): void
    {
        $principal = StubIdentity::create(['id' => 'principal-2']);
        $person    = StubSecondIdentity::create(['id' => 'person-2']);

        $person->givePermission(Permission::create(['name' => 'posts:read']));

        $this->app?->instance(SubjectResolver::class, new PrincipalSubjectResolver($principal, $person));

        [$code, $output] = self::why(['subject' => StubSecondIdentity::class . ':person-2', 'action' => 'posts:read', '--format' => 'json']);

        $request = self::decoded($output)['request'];

        self::assertSame(0, $code);
        self::assertSame('allow', self::decoded($output)['effect']);
        self::assertSame(['type' => $principal->getMorphClass(), 'id' => 'principal-2'], $request['subject'] ?? null);
        self::assertSame(['type' => $person->getMorphClass(), 'id' => 'person-2'], $request['identity'] ?? null);
    }

    /**
     * A console subject resolver the application binds resolves the subject,
     * and a session it gives the subject is dropped.
     *
     * @return void
     */
    public function testUsesTheBoundConsoleSubjectResolver(): void
    {
        $user = $this->editor('user-13');

        $resolver = new FixedConsoleSubjectResolver(new Subject($user, $user, session: PrincipalSubjectResolver::SESSION));

        $this->app?->instance(ConsoleSubjectResolver::class, $resolver);

        [$code, $output] = self::why(['subject' => 'operator-choice', 'action' => 'posts:edit', '--format' => 'json']);

        self::assertSame(0, $code);
        self::assertSame('allow', self::decoded($output)['effect']);
        self::assertSame(['type' => $user->getMorphClass(), 'id' => 'user-13'], self::decoded($output)['request']['subject'] ?? null);
        self::assertSame(['operator-choice'], $resolver->references);
        self::assertStringNotContainsString(PrincipalSubjectResolver::SESSION, $output);
    }

    /**
     * Return each invalid invocation and the error it is refused with.
     *
     * @return iterable<string, array{array<string, string|null>, string}>
     */
    public static function invalidInvocations(): iterable
    {
        $input   = 'The --context option supplies the input namespace alone and cannot fill the trusted namespace ';
        $context = 'The --context option must be a JSON object, read as the input namespace.';

        yield 'malformed JSON' => [['--context' => '{"purpose":"' . self::SECRET . '"'], 'The --context option must be valid JSON.'];
        yield 'empty JSON' => [['--context' => ''], 'The --context option must be valid JSON.'];
        yield 'a list' => [['--context' => '["' . self::SECRET . '"]'], $context];
        yield 'a string' => [['--context' => '"' . self::SECRET . '"'], $context];
        yield 'a number' => [['--context' => '42'], $context];
        yield 'null' => [['--context' => 'null'], $context];
        yield 'authentication' => [['--context' => '{"authentication":{"guard":"' . self::SECRET . '"}}'], $input . '\'authentication\'.'];
        yield 'subject' => [['--context' => '{"subject":"' . self::SECRET . '"}'], $input . '\'subject\'.'];
        yield 'resource' => [['--context' => '{"resource":{"status":"' . self::SECRET . '"}}'], $input . '\'resource\'.'];
        yield 'request' => [['--context' => '{"purpose":"x","request":{"ip":"' . self::SECRET . '"}}'], $input . '\'request\'.'];
        yield 'environment' => [['--context' => '{"environment":"' . self::SECRET . '"}'], $input . '\'environment\'.'];
        yield 'a dotted key' => [['--context' => '{"request.ip":"' . self::SECRET . '"}'], $input . '\'request\'.'];
        yield 'an unknown format' => [['--format' => 'xml'], 'The --format option must be text or json.'];
        yield 'a tenant without a key' => [['--tenant' => 'team'], 'The --tenant option must be in the format {morphType}:{key} (e.g. team:1).'];
        yield 'a tenant without a type' => [['--tenant' => ':1'], 'The --tenant option must be in the format {morphType}:{key} (e.g. team:1).'];
        yield 'an empty tenant' => [['--tenant' => ''], 'The --tenant option must be in the format {morphType}:{key} (e.g. team:1).'];
        yield 'an unknown tenant' => [['--tenant' => StubIdentity::class . ':' . self::SECRET], 'The --tenant option names no saved row.'];
        yield 'an empty application' => [['--application' => ''], 'The --application option must name an application.'];
        yield 'a malformed subject' => [['subject' => 'user'], 'The subject must be in the format {morphType}:{key} (e.g. user:1).'];
        yield 'an unknown subject type' => [['subject' => self::SECRET . ':1'], 'The subject\'s type is not an Eloquent model.'];
        yield 'an unknown subject' => [['subject' => StubIdentity::class . ':' . self::SECRET], 'The subject names no saved row.'];
        yield 'a resource without a type' => [['resource' => ':42'], self::RESOURCE];
        yield 'a resource without a key' => [['resource' => 'post:'], self::RESOURCE];
        yield 'a bare tenant' => [['--tenant' => null], 'The --tenant option must be given a value.'];
        yield 'a bare application' => [['--application' => null], 'The --application option must be given a value.'];
        yield 'a bare context' => [['--context' => null], 'The --context option must be given a value.'];
        yield 'a bare format' => [['--format' => null], 'The --format option must be given a value.'];
        yield 'a bare tenant with the format' => [['--tenant' => null, '--format' => 'json'], 'The --tenant option must be given a value.'];
        yield 'an unknown option' => [['--as-of' => '2026-01-01'], 'The "--as-of" option does not exist.'];
        yield 'a missing action' => [['action' => null], 'Not enough arguments (missing: "action").'];
    }

    /**
     * Each invalid invocation exits 2 with an error naming what is wrong and no
     * value it was given.
     *
     * @param  array<string, string|null>  $parameters
     * @param  string  $message
     * @return void
     */
    #[DataProvider('invalidInvocations')]
    public function testRefusesAnInvalidInvocation(array $parameters, string $message): void
    {
        StubIdentity::create(['id' => 'user-14']);

        $parameters = [...['subject' => StubIdentity::class . ':user-14', 'action' => 'posts:edit'], ...$parameters];

        $given = \array_filter($parameters, static fn (?string $value, string $name): bool => $value !== null || \str_starts_with($name, '--'), \ARRAY_FILTER_USE_BOTH);

        [$code, $output] = self::why($given);

        self::assertSame(2, $code);
        self::assertSame($message . "\n", $output);
        self::assertStringNotContainsString(self::SECRET, $output);
    }

    /**
     * A context naming an application's own namespace is refused too.
     *
     * @return void
     */
    public function testRefusesTheApplicationsOwnNamespace(): void
    {
        StubIdentity::create(['id' => 'user-15']);

        $this->app?->make(ConfigRepository::class)->set('authorization.context.sources', [FailingContextSource::class]);
        $this->app?->forgetInstance(CheckContextFactory::class);

        [$code, $output] = self::why(['subject' => StubIdentity::class . ':user-15', 'action' => 'posts:edit', '--context' => '{"ledger":{"balance":1}}']);

        self::assertSame(2, $code);
        self::assertSame("The --context option supplies the input namespace alone and cannot fill the trusted namespace 'ledger'.\n", $output);
    }

    /**
     * A subject resolved ambiguously, or one that cannot be checked, is refused
     * with exit 2.
     *
     * @return void
     */
    public function testRefusesAnUnsupportedOrAmbiguousSubject(): void
    {
        $principal = StubIdentity::create(['id' => 'principal-3']);
        $person    = StubSecondIdentity::create(['id' => 'person-3']);

        self::createTenant('tenant-e');
        StubIdentity::create(['id' => 'stranger-1']);

        [$code, $output] = self::why(['subject' => StubIdentity::class . ':stranger-1', 'action' => 'posts:edit']);

        self::assertSame(0, $code, $output);

        [$unsupported, $message] = self::why(['subject' => StubTenant::class . ':tenant-e', 'action' => 'posts:edit']);

        self::assertSame(2, $unsupported);
        self::assertStringContainsString('cannot be checked', $message);

        $this->app?->instance(SubjectResolver::class, new PrincipalSubjectResolver($principal, $person));

        [$ambiguous, $refusal] = self::why(['subject' => StubIdentity::class . ':stranger-1', 'action' => 'posts:edit']);

        self::assertSame(2, $ambiguous);
        self::assertStringContainsString('is ambiguous', $refusal);
    }

    /**
     * Return each subject or tenant whose key the key column cannot hold.
     *
     * @return iterable<string, array{array<string, string>, list<string>}>
     */
    public static function uncastableKeys(): iterable
    {
        $subject = NumberedIdentity::class . ':abc';

        yield 'a subject' => [['subject' => $subject], ['The subject names no saved row.', 'The subject could not be resolved.']];
        yield 'a tenant' => [['--tenant' => $subject], ['The --tenant option names no saved row.', 'The --tenant option could not be resolved.']];
    }

    /**
     * A subject or tenant whose key the key column cannot hold exits 2, as not
     * found or, on a database that refuses to compare it, as unresolvable,
     * never with the database's error.
     *
     * @param  array<string, string>  $parameters
     * @param  list<string>  $messages
     * @return void
     */
    #[DataProvider('uncastableKeys')]
    public function testRefusesAKeyTheKeyColumnCannotHold(array $parameters, array $messages): void
    {
        StubIdentity::create(['id' => 'user-24']);

        [$code, $output] = self::why([...['subject' => StubIdentity::class . ':user-24', 'action' => 'posts:edit'], ...$parameters]);

        self::assertSame(2, $code);
        self::assertContains(\rtrim($output, "\n"), $messages);
    }

    /**
     * A subject or tenant whose lookup fails exits 2, naming the argument and
     * neither the failure nor the value it holds.
     *
     * @return void
     */
    public function testRefusesALookupThatFails(): void
    {
        $tenant = self::createTenant('tenant-h');

        StubIdentity::create(['id' => 'user-25']);
        StubIdentity::retrieved(static function (): never {
            throw new \RuntimeException(self::SECRET);
        });

        $subject = self::why(['subject' => StubIdentity::class . ':user-25', 'action' => 'posts:edit']);

        StubTenant::retrieved(static function (): never {
            throw new \InvalidArgumentException(self::SECRET);
        });

        $scope = self::why(['subject' => 'nothing:1', 'action' => 'posts:edit', '--tenant' => $tenant->getMorphClass() . ':tenant-h']);

        self::assertSame([2, "The subject could not be resolved.\n"], $subject);
        self::assertSame([2, "The --tenant option could not be resolved.\n"], $scope);
    }

    /**
     * A subject resolver that fails exits 2, naming the subject and neither the
     * failure nor the value it holds, whatever it throws.
     *
     * @return void
     */
    public function testRefusesASubjectResolverThatFails(): void
    {
        StubIdentity::create(['id' => 'user-26']);

        foreach ([new \RuntimeException(self::SECRET), new \InvalidArgumentException(self::SECRET)] as $failure) {
            $this->app?->instance(SubjectResolver::class, new FailingSubjectResolver($failure));

            self::assertSame([2, "The subject could not be resolved.\n"], self::why(['subject' => StubIdentity::class . ':user-26', 'action' => 'posts:edit']));
        }
    }

    /**
     * A console subject resolver that fails other than by refusing the subject
     * exits 2 without naming the failure; one that refuses it exits 2 with what
     * its refusal says is wrong, naming the subject argument alone, and one
     * that refuses it in words of its own as unresolvable.
     *
     * @return void
     */
    public function testRefusesAConsoleSubjectResolverThatFails(): void
    {
        $failures = [
            "The subject could not be resolved.\n" => [
                new \RuntimeException(self::SECRET),
                new \InvalidArgumentException(self::SECRET),
                new UnresolvedSubjectException(self::SECRET),
            ],
            "The subject names no saved row.\n"              => [UnresolvedSubjectException::notFound('staff:1')],
            "The subject's type is not an Eloquent model.\n" => [UnresolvedSubjectException::unknownType('staff')],
        ];

        foreach ($failures as $message => $thrown) {
            foreach ($thrown as $failure) {
                $this->app?->instance(ConsoleSubjectResolver::class, new FixedConsoleSubjectResolver(new Subject(new StubIdentity), $failure));

                self::assertSame([2, $message], self::why(['subject' => 'staff:1', 'action' => 'posts:edit']));
            }
        }
    }

    /**
     * Run from the command line, an unknown option exits 2 with its error on
     * the standard error, and an option after `--` is no option but the
     * resource, which is never refused as a bare option.
     *
     * @return void
     */
    public function testRefusesAnUnknownOptionFromTheCommandLine(): void
    {
        $this->editor('user-27');

        $subject = StubIdentity::class . ':user-27';

        self::assertSame([2, "The \"--as-of\" option does not exist.\n"], $this->commandLine(['authorization:why', $subject, 'posts:edit', '--as-of=2026-01-01']));
        self::assertSame([2, "Not enough arguments (missing: \"action\").\n"], $this->commandLine(['authorization:why', $subject]));

        [$code, $output] = $this->commandLine(['authorization:why', $subject, 'posts:edit', '--format=json', '--', '--tenant']);

        self::assertSame(0, $code);
        self::assertSame('--tenant', self::decoded($output)['request']['resource'] ?? null);
    }

    /**
     * Errors go to the standard error, leaving the standard output empty, and
     * an explanation goes to the standard output alone.
     *
     * @return void
     */
    public function testErrorsGoToTheStandardError(): void
    {
        $this->editor('user-16');

        $refused = $this->tester();

        self::assertSame(2, $refused->execute(['subject' => 'bad', 'action' => 'posts:edit'], ['capture_stderr_separately' => true]));
        self::assertSame('', $refused->getDisplay());
        self::assertStringContainsString('The subject must be in the format', $refused->getErrorOutput());

        $unbound = $this->tester();

        self::assertSame(2, $unbound->execute(['subject' => 'bad', '--as-of' => 'x'], ['capture_stderr_separately' => true]));
        self::assertSame('', $unbound->getDisplay());
        self::assertSame("The \"--as-of\" option does not exist.\n", $unbound->getErrorOutput());

        $explained = $this->tester();

        $code = $explained->execute(['subject' => StubIdentity::class . ':user-16', 'action' => 'posts:edit', '--format' => 'json'], ['capture_stderr_separately' => true]);

        self::assertSame(0, $code);
        self::assertSame('', $explained->getErrorOutput());
        self::assertSame('allow', self::decoded($explained->getDisplay())['effect']);
    }

    /**
     * Markup and control characters in an error are escaped, so neither styles
     * nor moves the terminal, even on a decorated output: an unknown option is
     * named as it was given, escaped, and a subject is never named at all.
     *
     * @return void
     */
    public function testErrorsEscapeMarkupAndControlCharacters(): void
    {
        $tester = $this->tester();

        $tester->execute(['subject' => 'user:1', 'action' => 'posts:edit', "--<fg=red>evil\e[2J\u{85}</>" => 'x'], ['capture_stderr_separately' => true, 'decorated' => true]);

        $error = $tester->getErrorOutput();

        self::assertStringContainsString('"--<fg=red>evil\u001b[2J\u0085</>"', $error);
        self::assertStringNotContainsString("\e[31m", $error);
        self::assertStringNotContainsString("\e[2J", $error);
        self::assertStringNotContainsString("\u{85}", $error);
        self::assertStringStartsWith("\e[37;41m", $error);

        $subject = $this->tester();

        $subject->execute(['subject' => "<fg=red>evil\e[2J\u{85}</>:1", 'action' => 'posts:edit'], ['capture_stderr_separately' => true, 'decorated' => true]);

        self::assertStringContainsString('The subject\'s type is not an Eloquent model.', $subject->getErrorOutput());
        self::assertStringNotContainsString('evil', $subject->getErrorOutput());
    }

    /**
     * An error holding a byte that is not UTF-8, such as an 8-bit control, is
     * escaped whole, and format and bidirectional characters are escaped, so
     * none reaches the terminal.
     *
     * @return void
     */
    public function testErrorsEscapeInvalidBytesAndFormatCharacters(): void
    {
        [$code, $invalid] = self::why(['subject' => 'user:1', 'action' => 'posts:edit', "--\x9b2J" => 'x']);
        [, $bidi]         = self::why(['subject' => 'user:1', 'action' => 'posts:edit', "--a\u{202E}b\u{200B}c\u{2028}d" => 'x']);

        self::assertSame(2, $code);
        self::assertSame("The \\\"--\\ufffd2J\\\" option does not exist.\n", $invalid);
        self::assertSame("The \"--a\\u202eb\\u200bc\\u2028d\" option does not exist.\n", $bidi);
    }

    /**
     * Markup in a name the explanation prints, the resource and the application
     * here, is escaped in the text output.
     *
     * @return void
     */
    public function testTextEscapesMarkupInNames(): void
    {
        $this->editor('user-17');

        [$code, $output] = self::why(['subject' => StubIdentity::class . ':user-17', 'action' => 'posts:edit', 'resource' => '<fg=red>post</>', '--application' => "<b>app\e</b>"]);

        self::assertSame(0, $code);
        self::assertStringContainsString('on "\u003Cfg=red\u003Epost\u003C/\u003E"', $output);
        self::assertStringContainsString('for application "\u003Cb\u003Eapp\u001b\u003C/b\u003E"', $output);
        self::assertStringNotContainsString('<fg=red>', $output);
        self::assertStringNotContainsString("\e", $output);
    }

    /**
     * Run the command, returning its exit code and everything it wrote.
     *
     * @param  array<string, bool|string|null>  $parameters
     * @return array{int, string}
     */
    private static function why(array $parameters): array
    {
        $code = Artisan::call(WhyCommand::NAME, $parameters);

        return [$code, Artisan::output()];
    }

    /**
     * Run the command line through the console kernel, returning its exit code
     * and everything it wrote.
     *
     * @param  list<string>  $arguments
     * @return array{int, string}
     */
    private function commandLine(array $arguments): array
    {
        $kernel = $this->app?->make(Kernel::class);
        $output = new BufferedOutput;

        self::assertInstanceOf(Kernel::class, $kernel);

        return [$kernel->handle(new ArgvInput(['artisan', ...$arguments]), $output), $output->fetch()];
    }

    /**
     * Return a tester for the registered command, which can capture the
     * standard error apart from the standard output.
     *
     * @return \Symfony\Component\Console\Tester\CommandTester
     */
    private function tester(): CommandTester
    {
        $kernel = $this->app?->make(Kernel::class);

        self::assertInstanceOf(Kernel::class, $kernel);

        return new CommandTester($kernel->all()['authorization:why']);
    }

    /**
     * Return the JSON document decoded.
     *
     * @param  string  $output
     * @return array<string, mixed>
     */
    private static function decoded(string $output): array
    {
        $document = \json_decode($output, true, 512, \JSON_THROW_ON_ERROR);

        self::assertIsArray($document);

        /** @var array<string, mixed> $document */
        return $document;
    }

    /**
     * Create an identity holding `posts:edit` through the `editor` role.
     *
     * @param  string  $id
     * @return \Tests\Feature\Stubs\StubIdentity
     */
    private function editor(string $id): StubIdentity
    {
        $role = Role::query()->where('name', 'editor')->first() ?? Role::create(['name' => 'editor', 'guard' => 'web']);
        $user = StubIdentity::create(['id' => $id]);

        if (!$role->hasPermission('posts:edit')) {
            $role->givePermissionTo(Permission::create(['name' => 'posts:edit', 'guard' => 'web']));
        }

        $user->assignRole($role);

        return $user;
    }

    /**
     * Use the provider for the attributes of resources of the type.
     *
     * @param  string  $type
     * @param  \Tests\Feature\Stubs\RecordingResourceAttributes  $provider
     * @return void
     */
    private function useResourceAttributes(string $type, RecordingResourceAttributes $provider): void
    {
        $this->app?->instance(RecordingResourceAttributes::class, $provider);
        $this->app?->make(ConfigRepository::class)->set('authorization.attributes.resources', [$type => RecordingResourceAttributes::class]);
        $this->app?->forgetInstance(CheckContextFactory::class);
        $this->app?->forgetInstance('authorization');
    }

    /**
     * Attach the policy to the resource through the resource policy service.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @param  mixed  $resource
     * @return void
     *
     * @throws \Throwable
     */
    private static function attach(Policy $policy, mixed $resource): void
    {
        $service = ResourcePolicyService::instance();

        self::assertInstanceOf(ResourcePolicyService::class, $service);

        $service->attach($policy, $resource);
    }

    /**
     * Return a resource policy statement, `share`, allowing the identity the
     * action, on the conditions.
     *
     * @param  \Tests\Feature\Stubs\StubIdentity  $identity
     * @param  string  $action
     * @param  array<string, mixed>  $conditions
     * @return array<string, mixed>
     */
    private static function share(StubIdentity $identity, string $action, array $conditions = []): array
    {
        $principal = Reference::of($identity);
        $statement = ['sid' => 'share', 'effect' => 'allow', 'actions' => [$action], 'principals' => [$principal->getMorphClass() . ':' . $principal->getKey()]];

        return $conditions === [] ? $statement : [...$statement, 'conditions' => $conditions];
    }

    /**
     * Return the outcome of every condition test the explanation's JSON
     * records, keyed by the key it tested.
     *
     * @param  array<string, mixed>  $document
     * @return array<string, mixed>
     */
    private static function outcomes(array $document): array
    {
        $outcomes = [];

        /** @var list<array{steps: list<array{tests: list<array{key: string, outcome: string}>|string}>}> $stages */
        $stages = $document['stages'];

        foreach ($stages as $stage) {
            foreach ($stage['steps'] as $step) {
                foreach (\is_array($step['tests']) ? $step['tests'] : [] as $test) {
                    $outcomes[$test['key']] = $test['outcome'];
                }
            }
        }

        return $outcomes;
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

    /**
     * Return the reference to the model as the text output writes it.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @return string
     */
    private static function escaped(Model $model): string
    {
        $reference = Reference::of($model);

        return \str_replace('\\', '\\\\', $reference->getMorphClass()) . ':' . $reference->getKey();
    }
}
