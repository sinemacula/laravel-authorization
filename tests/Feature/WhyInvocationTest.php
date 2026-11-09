<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Container\Container;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Database\Eloquent\Relations\Relation;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Console\Support\WhyInvocation;
use SineMacula\Laravel\Authorization\Context\CheckContextFactory;
use SineMacula\Laravel\Authorization\Contracts\AuthenticationRequirementChecker;
use SineMacula\Laravel\Authorization\Evaluation\RequirementResult;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\AuthorizationScope;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResourceReference;
use Tests\Concerns\ActsAsTenant;
use Tests\Feature\Stubs\FailingContextSource;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubRequirementChecker;
use Tests\Feature\Stubs\StubTenant;
use Tests\TestCase;

/**
 * Feature tests for `WhyInvocation`, which reads what one `authorization:why`
 * invocation asks from its arguments and options, refusing what it cannot read,
 * and explains the check on the trusted path in the scope it names.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(WhyInvocation::class)]
final class WhyInvocationTest extends TestCase
{
    use ActsAsTenant;

    /** @var string A value a failure holds, which no refusal may carry. */
    private const string SECRET = 'sentinel-failure-3c9e';

    /** @var string The refusal of a resource with a colon but an empty type or key. */
    private const string RESOURCE = 'The resource must be in the format {morphType}:{key} or {morphType}:* (e.g. post:42), or be given with --opaque.';

    /** @var list<string> The trusted namespaces the tests refuse. */
    private const array TRUSTED = ['authentication', 'request', 'environment', 'subject', 'resource'];

    /**
     * Clear the morph map a test sets.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Relation::morphMap([], false);

        parent::tearDown();
    }

    /**
     * With no option given, the invocation is the action on no resource, in the
     * platform, on no application, with no input, as text.
     *
     * @return void
     */
    public function testDefaultsToThePlatformWithNoInputAsText(): void
    {
        $invocation = self::of(['action' => 'posts:read'], []);

        self::assertSame('posts:read', $invocation->action);
        self::assertNull($invocation->resource);
        self::assertNull($invocation->scope->tenant);
        self::assertNull($invocation->scope->application);
        self::assertNull($invocation->scope->resource);
        self::assertSame([], $invocation->input);
        self::assertFalse($invocation->isJson);
    }

    /**
     * A `{morphType}:{key}` resource is the `(type, id)` pair of that record,
     * its key keeping any colon, and `{morphType}:*` the type alone: a model
     * class as it is, any other type as a reference to the type.
     *
     * @return void
     */
    public function testReadsARecordAndATypeAlone(): void
    {
        self::assertSame(['post', '42'], self::resource('post:42'));
        self::assertSame(['post', 'a:b'], self::resource('post:a:b'));
        self::assertSame([StubTenant::class, 'tenant-1'], self::resource(StubTenant::class . ':tenant-1'));
        self::assertEquals(ResourceReference::type('post'), self::resource('post:*'));
        self::assertSame(StubTenant::class, self::resource(StubTenant::class . ':*'));
        self::assertSame(['post', '42'], self::resource('post:42', ['opaque' => false]));
    }

    /**
     * A resource with no colon, or any resource with `--opaque`, is the opaque
     * identifier it is, and only a string is a resource.
     *
     * @return void
     */
    public function testKeepsAnOpaqueResourceAsGiven(): void
    {
        self::assertSame('posts/42', self::resource('posts/42'));
        self::assertSame('', self::resource(''));
        self::assertSame('post:42', self::resource('post:42', ['opaque' => true]));
        self::assertSame('post:*', self::resource('post:*', ['opaque' => true]));
        self::assertSame(':', self::resource(':', ['opaque' => true]));
        self::assertNull(self::resource(null));
        self::assertNull(self::resource(['post', '42']));
        self::assertNull(self::resource(['post', '42'], ['opaque' => true]));
    }

    /**
     * A resource with a colon but an empty type or key is refused.
     *
     * @return void
     */
    public function testRefusesAResourceWithAnEmptyTypeOrKey(): void
    {
        foreach ([':42', 'post:', ':', ':*'] as $resource) {
            $this->assertRefused(['action' => 'a', 'resource' => $resource], [], self::RESOURCE);
        }
    }

    /**
     * An action that is not a string is refused.
     *
     * @return void
     */
    public function testRefusesAMissingAction(): void
    {
        $this->assertRefused([], [], 'The action must be given.');
        $this->assertRefused(['action' => 42], [], 'The action must be given.');
    }

    /**
     * Each format: text, the default, or json; anything else is refused.
     *
     * @return void
     */
    public function testReadsTheFormat(): void
    {
        self::assertFalse(self::of(['action' => 'a'], ['format' => null])->isJson);
        self::assertFalse(self::of(['action' => 'a'], ['format' => 'text'])->isJson);
        self::assertTrue(self::of(['action' => 'a'], ['format' => 'json'])->isJson);

        foreach (['xml', 'JSON', '', true] as $format) {
            $this->assertRefused(['action' => 'a'], ['format' => $format], 'The --format option must be text or json.');
        }
    }

    /**
     * The application is the one named, on the platform too; an empty one or
     * one that is not a string is refused.
     *
     * @return void
     */
    public function testReadsTheApplication(): void
    {
        self::assertSame('web', self::of(['action' => 'a'], ['application' => 'web'])->scope->application);
        self::assertNull(self::of(['action' => 'a'], ['application' => 'web'])->scope->tenant);

        foreach (['', 42] as $application) {
            $this->assertRefused(['action' => 'a'], ['application' => $application], 'The --application option must name an application.');
        }
    }

    /**
     * A tenant whose type names an Eloquent model, by class or morph alias, is
     * that model's row, named by its morph class, with the application.
     *
     * @return void
     */
    public function testATenantModelIsNamedByItsMorphClass(): void
    {
        $tenant = self::createTenant('tenant-1');
        $scope  = self::of(['action' => 'a'], ['tenant' => StubTenant::class . ':tenant-1', 'application' => 'web'])->scope;

        self::assertEquals(Reference::of($tenant), $scope->tenant);
        self::assertSame('web', $scope->application);

        Relation::morphMap(['team' => StubTenant::class]);

        self::assertEquals(new Reference('team', 'tenant-1'), self::of(['action' => 'a'], ['tenant' => StubTenant::class . ':tenant-1'])->scope->tenant);
        self::assertEquals(new Reference('team', 'tenant-1'), self::of(['action' => 'a'], ['tenant' => 'team:tenant-1'])->scope->tenant);

        $this->assertRefused(['action' => 'a'], ['tenant' => 'team:missing'], 'The --tenant option names no saved row.');
    }

    /**
     * A tenant type that names no model is the reference as given, its key
     * keeping any colon.
     *
     * @return void
     */
    public function testATenantTypeNamingNoModelIsTheReferenceAsGiven(): void
    {
        self::assertEquals(new Reference('org', 'acme:eu'), self::of(['action' => 'a'], ['tenant' => 'org:acme:eu'])->scope->tenant);
    }

    /**
     * A tenant that is malformed, or whose model has no row with the key, is
     * refused.
     *
     * @return void
     */
    public function testRefusesAnUnreadableTenant(): void
    {
        $format = 'The --tenant option must be in the format {morphType}:{key} (e.g. team:1).';

        foreach (['', 'team', ':1', 'team:', 42] as $tenant) {
            $this->assertRefused(['action' => 'a'], ['tenant' => $tenant], $format);
        }

        $this->assertRefused(['action' => 'a'], ['tenant' => StubTenant::class . ':missing'], 'The --tenant option names no saved row.');
    }

    /**
     * A tenant whose lookup fails is refused without naming the failure or the
     * value it holds.
     *
     * @return void
     */
    public function testRefusesATenantWhoseLookupFails(): void
    {
        self::createTenant('tenant-5');

        StubTenant::retrieved(static function (): never {
            throw new \RuntimeException(self::SECRET);
        });

        $this->assertRefused(['action' => 'a'], ['tenant' => StubTenant::class . ':tenant-5'], 'The --tenant option could not be resolved.');
    }

    /**
     * The context is a JSON object read as the input namespace, nested values,
     * numeric keys, an `input` key and a trusted name below the top kept as
     * they are.
     *
     * @return void
     */
    public function testTheContextIsTheInput(): void
    {
        $context = '{"purpose":"support","flags":{"request":true,"list":[1,null]},"0":"zero","input":{"a":1}}';

        self::assertSame(
            ['purpose' => 'support', 'flags' => ['request' => true, 'list' => [1, null]], 0 => 'zero', 'input' => ['a' => 1]],
            self::of(['action' => 'a'], ['context' => $context])->input,
        );
        self::assertSame([], self::of(['action' => 'a'], ['context' => '{}'])->input);
        self::assertSame(['deep'], \array_keys(self::of(['action' => 'a'], ['context' => '{"deep":' . \str_repeat('[', 510) . \str_repeat(']', 510) . '}'])->input));
        self::assertSame(['requests' => 1, 'requested.ip' => 2], self::of(['action' => 'a'], ['context' => '{"requests":1,"requested.ip":2}'])->input);
    }

    /**
     * Return each context that is no JSON object, and its refusal.
     *
     * @return iterable<string, array{mixed, string}>
     */
    public static function unreadableContexts(): iterable
    {
        $object = 'The --context option must be a JSON object, read as the input namespace.';
        $json   = 'The --context option must be valid JSON.';

        yield 'malformed' => ['{"a":', $json];
        yield 'empty' => ['', $json];
        yield 'not a string' => [42, $json];
        yield 'too deep' => [\str_repeat('[', 512) . \str_repeat(']', 512), $json];
        yield 'a list' => ['[]', $object];
        yield 'a string' => ['"a"', $object];
        yield 'a number' => ['1', $object];
        yield 'null' => ['null', $object];
        yield 'true' => ['true', $object];
    }

    /**
     * Malformed JSON, and JSON that is not an object, are refused.
     *
     * @param  mixed  $context
     * @param  string  $message
     * @return void
     */
    #[DataProvider('unreadableContexts')]
    public function testRefusesAContextThatIsNoObject(mixed $context, string $message): void
    {
        $this->assertRefused(['action' => 'a'], ['context' => $context], $message);
    }

    /**
     * A top-level key naming a trusted namespace, or a dotted key starting with
     * one, is refused, naming the namespace.
     *
     * @return void
     */
    public function testRefusesAContextFillingATrustedNamespace(): void
    {
        foreach (self::TRUSTED as $namespace) {
            $message = "The --context option supplies the input namespace alone and cannot fill the trusted namespace '{$namespace}'.";

            foreach (["{\"{$namespace}\":1}", "{\"ok\":1,\"{$namespace}.key\":1}"] as $context) {
                $this->assertRefused(['action' => 'a'], ['context' => $context], $message);
            }
        }
    }

    /**
     * The check is explained about the subject in the scope, both as the
     * subject's and as the ambient grant scope, not the tenant in place, which
     * is back afterwards; the subject has no session.
     *
     * @return void
     */
    public function testExplainsInTheScopeNamed(): void
    {
        $ambient = self::createTenant('tenant-2');
        $tenant  = self::createTenant('tenant-3');
        $user    = StubIdentity::create(['id' => 'user-1']);
        $checker = new StubRequirementChecker(RequirementResult::met());

        $user->givePermission(Permission::create(['name' => 'posts:read']), null, $tenant, true, 'web');
        $user->attachPolicy(Policy::create(['name' => 'stepped', 'document' => ['statements' => [
            ['effect' => 'allow', 'actions' => ['posts:mfa'], 'conditions' => ['authentication_requirement' => ['authentication' => ['multifactor' => ['max_age' => 900]]]]],
        ]]]));

        $this->actAsTenant($ambient);
        $this->app?->instance(AuthenticationRequirementChecker::class, $checker);
        $this->app?->forgetInstance(CheckContextFactory::class);
        $this->app?->forgetInstance('authorization');

        $invocation = self::of(['action' => 'posts:read'], ['tenant' => StubTenant::class . ':tenant-3', 'application' => 'web']);
        $subject    = new Subject($user, $user, $ambient, 'api', 'web', 'session-1');

        $explanation = $invocation->explain(self::manager(), $subject);
        $request     = $explanation->evidence?->request;

        self::assertTrue($explanation->isAllowed());
        self::assertNotNull($request);
        self::assertEquals(Reference::of($tenant), $request->decided->tenant);
        self::assertSame('web', $request->decided->application);
        self::assertEquals(Reference::of($tenant), $request->requested->tenant);
        self::assertSame([StubTenant::class, 'tenant-2'], TenantScope::currentTenant());

        $scope    = AuthorizationScope::platform();
        $withheld = self::of(['action' => 'posts:mfa'], [])->explain(self::manager(), $subject);
        $proved   = $scope->within(static fn (): bool => self::manager()->for($scope->subjectIn($subject))->check('posts:mfa')->isAllowed());

        self::assertFalse($withheld->isAllowed());
        self::assertTrue($proved);
        self::assertCount(1, $checker->calls);
        self::assertSame('session-1', $checker->calls[0][1]->session);
    }

    /**
     * The tenant in place is back after a check that throws.
     *
     * @return void
     */
    public function testRestoresTheScopeWhenTheCheckThrows(): void
    {
        $ambient = self::createTenant('tenant-4');
        $user    = StubIdentity::create(['id' => 'user-2']);

        $this->actAsTenant($ambient);

        $user->attachPolicy(Policy::create(['name' => 'ledger', 'document' => ['statements' => [
            ['effect' => 'allow', 'actions' => ['posts:read'], 'conditions' => ['eq' => ['ledger.balance' => 1]]],
        ]]]));

        $this->app?->make(ConfigRepository::class)->set('authorization.context.sources', [FailingContextSource::class]);
        $this->app?->forgetInstance(CheckContextFactory::class);
        $this->app?->forgetInstance('authorization');

        try {
            self::of(['action' => 'posts:read'], [])->explain(self::manager(), new Subject($user, $user));

            self::fail('The check throws.');
        } catch (\RuntimeException $exception) {
            self::assertSame(FailingContextSource::MESSAGE, $exception->getMessage());
        }

        self::assertSame([StubTenant::class, 'tenant-4'], TenantScope::currentTenant());
    }

    /**
     * Read the invocation from the arguments and options, the trusted
     * namespaces refused.
     *
     * @param  array<string, mixed>  $arguments
     * @param  array<string, mixed>  $options
     * @return \SineMacula\Laravel\Authorization\Console\Support\WhyInvocation
     *
     * @throws \InvalidArgumentException
     */
    private static function of(array $arguments, array $options): WhyInvocation
    {
        return WhyInvocation::of($arguments, $options, self::TRUSTED);
    }

    /**
     * Return the resource the invocation reads from the argument, with the
     * options.
     *
     * @param  mixed  $resource
     * @param  array<string, mixed>  $options
     * @return array{string, string}|\SineMacula\Laravel\Authorization\Support\ResourceReference|string|null
     *
     * @throws \InvalidArgumentException
     */
    private static function resource(mixed $resource, array $options = []): array|ResourceReference|string|null
    {
        return self::of(['action' => 'posts:read', 'resource' => $resource], $options)->resource;
    }

    /**
     * Assert the arguments and options are refused with the message.
     *
     * @param  array<string, mixed>  $arguments
     * @param  array<string, mixed>  $options
     * @param  string  $message
     * @return void
     */
    private function assertRefused(array $arguments, array $options, string $message): void
    {
        try {
            self::of($arguments, $options);

            self::fail("Refused: {$message}");
        } catch (\InvalidArgumentException $exception) {
            self::assertSame($message, $exception->getMessage());
        }
    }

    /**
     * Return the authorization manager.
     *
     * @return \SineMacula\Laravel\Authorization\AuthorizationManager
     */
    private static function manager(): AuthorizationManager
    {
        $manager = Container::getInstance()->make(AuthorizationManager::class);

        self::assertInstanceOf(AuthorizationManager::class, $manager);

        return $manager;
    }
}
