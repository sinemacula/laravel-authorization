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
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Events\DecisionEvaluated;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\AuthorizationScope;
use SineMacula\Laravel\Authorization\Support\Reference;
use Symfony\Component\Console\Tester\CommandTester;
use Tests\Concerns\ActsAsTenant;
use Tests\Feature\Stubs\FailingContextSource;
use Tests\Feature\Stubs\FixedConsoleSubjectResolver;
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

        self::assertSame([], $posts->calls);
    }

    /**
     * The resource is the string reference `check()` takes, passed as given: no
     * model column is read and no attribute provider supplies an opaque
     * reference, so a condition on the resource finds its key missing and
     * reports it so.
     *
     * @return void
     */
    public function testResourceAttributesComeOnlyFromProviders(): void
    {
        $user  = StubIdentity::create(['id' => 'user-7']);
        $posts = new RecordingResourceAttributes;

        $user->attachPolicy(self::policy('drafts', [['effect' => 'allow', 'actions' => ['posts:edit'], 'conditions' => ['eq' => ['resource.status' => 'draft']]]]));
        $this->useResourceAttributes($user->getMorphClass(), $posts);

        [$code, $output] = self::why(['subject' => StubIdentity::class . ':user-7', 'action' => 'posts:edit', 'resource' => StubIdentity::class . ':user-7', '--format' => 'json']);

        $document = self::decoded($output);

        self::assertSame(0, $code);
        self::assertSame('deny', $document['effect']);
        self::assertSame(['resource.status'], $document['missing_keys']);
        self::assertSame(StubIdentity::class . ':user-7', $document['request']['resource'] ?? null);
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

        self::assertArrayHasKey('resource', self::decoded($output)['request']);
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
     * @return iterable<string, array{array<string, string>, string}>
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
        yield 'an unknown tenant' => [['--tenant' => StubIdentity::class . ':missing'], 'No tenant \'Tests\Feature\Stubs\StubIdentity:missing\' was found.'];
        yield 'an empty application' => [['--application' => ''], 'The --application option must name an application.'];
        yield 'a malformed subject' => [['subject' => 'user'], 'The subject must be in the format {morphType}:{key} (e.g. user:1).'];
        yield 'an unknown subject type' => [['subject' => 'nothing:1'], 'The subject type \'nothing\' is not an Eloquent model.'];
        yield 'an unknown subject' => [['subject' => StubIdentity::class . ':missing'], 'No subject \'Tests\Feature\Stubs\StubIdentity:missing\' was found.'];
    }

    /**
     * Each invalid invocation exits 2 with an error naming what is wrong and no
     * value it was given.
     *
     * @param  array<string, string>  $parameters
     * @param  string  $message
     * @return void
     */
    #[DataProvider('invalidInvocations')]
    public function testRefusesAnInvalidInvocation(array $parameters, string $message): void
    {
        StubIdentity::create(['id' => 'user-14']);

        [$code, $output] = self::why([...['subject' => StubIdentity::class . ':user-14', 'action' => 'posts:edit'], ...$parameters]);

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

        $explained = $this->tester();

        $code = $explained->execute(['subject' => StubIdentity::class . ':user-16', 'action' => 'posts:edit', '--format' => 'json'], ['capture_stderr_separately' => true]);

        self::assertSame(0, $code);
        self::assertSame('', $explained->getErrorOutput());
        self::assertSame('allow', self::decoded($explained->getDisplay())['effect']);
    }

    /**
     * Markup and control characters in an error are escaped, so neither styles
     * nor moves the terminal, even on a decorated output.
     *
     * @return void
     */
    public function testErrorsEscapeMarkupAndControlCharacters(): void
    {
        $tester = $this->tester();

        $tester->execute(['subject' => "<fg=red>evil\e[2J\u{85}</>:1", 'action' => 'posts:edit'], ['capture_stderr_separately' => true, 'decorated' => true]);

        $error = $tester->getErrorOutput();

        self::assertStringContainsString('\'<fg=red>evil\u001b[2J\u0085</>\'', $error);
        self::assertStringNotContainsString("\e[31m", $error);
        self::assertStringNotContainsString("\e[2J", $error);
        self::assertStringNotContainsString("\u{85}", $error);
        self::assertStringStartsWith("\e[37;41m", $error);
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
     * @param  array<string, string>  $parameters
     * @return array{int, string}
     */
    private static function why(array $parameters): array
    {
        $code = Artisan::call('authorization:why', $parameters);

        return [$code, Artisan::output()];
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

        return \str_replace('\\', '\\\\', $reference->type) . ':' . $reference->id;
    }
}
