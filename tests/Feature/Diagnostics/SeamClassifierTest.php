<?php

declare(strict_types = 1);

namespace Tests\Feature\Diagnostics;

use Illuminate\Config\Repository;
use Illuminate\Container\Container;
use Illuminate\Foundation\Application;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Authorization\Contracts\ActionCatalogue;
use SineMacula\Laravel\Authorization\Contracts\GrantHook;
use SineMacula\Laravel\Authorization\Contracts\GrantUsageStore;
use SineMacula\Laravel\Authorization\Contracts\PolicyStore;
use SineMacula\Laravel\Authorization\Contracts\ScopeRegistry;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Diagnostics\BindingRegistry;
use SineMacula\Laravel\Authorization\Diagnostics\Declarations;
use SineMacula\Laravel\Authorization\Diagnostics\Enums\Lifetime;
use SineMacula\Laravel\Authorization\Diagnostics\Enums\Origin;
use SineMacula\Laravel\Authorization\Diagnostics\Inspector;
use SineMacula\Laravel\Authorization\Diagnostics\SeamClassifier;
use SineMacula\Laravel\Authorization\Diagnostics\SeamRow;
use SineMacula\Laravel\Authorization\Hooks\GrantHooks;
use SineMacula\Laravel\Authorization\Resolvers\FlatTenantTree;
use SineMacula\Laravel\Authorization\Support\DeclaredActionCatalogue;
use SineMacula\Laravel\Authorization\Usage\DatabaseGrantUsageStore;
use Tests\Feature\Stubs\DeferredBindingProvider;
use Tests\Fixtures\Diagnostics\ExplodingGrantHook;
use Tests\Fixtures\Diagnostics\ExplodingTenantTree;
use Tests\Fixtures\Diagnostics\Explosions;
use Tests\TestCase;

/**
 * Feature tests for telling where each seam's binding came from without
 * building it (N113, N118): the package's default, the configured class, a
 * binding made before the package registered or after it, of each kind, a
 * sibling's declared adapter, standing or overridden, a declared factory, an
 * unknown factory, a deferred provider not loaded yet, the extenders and an
 * alias.
 *
 * Every seam bound here explodes when it is built or called, and each test
 * checks that none was, and that whether each seam was resolved is the same
 * after classifying as before.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SeamClassifier::class)]
#[CoversClass(SeamRow::class)]
final class SeamClassifierTest extends TestCase
{
    /** @var string The path the closures of this file are shown under. */
    private const string FILE = 'tests/Feature/Diagnostics/SeamClassifierTest.php';

    /** @var list<class-string> The seams the matrix runs over: configurable or not, the usage store and the grant hook among them. */
    private const array CONTRACTS = [TenantTree::class, SubjectResolver::class, ActionCatalogue::class, GrantUsageStore::class, GrantHook::class];

    /**
     * Reset the count of seams built.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Explosions::$count = 0;
    }

    /**
     * Forget the deferred bindings and restore the suite's application as the
     * container's instance.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        DeferredBindingProvider::$objects = [];

        Container::setInstance($this->app);

        parent::tearDown();
    }

    /**
     * The package's default is reported with the class it builds and the
     * lifetime of the key its closure forwards to, not of the closure.
     *
     * @return void
     */
    public function testThePackageDefaultIsReported(): void
    {
        $app  = self::registered();
        $rows = self::classifyAll($app);

        self::assertSame(Origin::PACKAGE_DEFAULT, $rows[TenantTree::class]->origin);
        self::assertSame(FlatTenantTree::class, $rows[TenantTree::class]->class());
        self::assertSame(Lifetime::SCOPED, $rows[TenantTree::class]->lifetime);
        self::assertSame('authorization.tenant_tree', $rows[TenantTree::class]->toArray()['config_key']);
        self::assertSame(DeclaredActionCatalogue::class, $rows[ActionCatalogue::class]->class());
        self::assertSame(DatabaseGrantUsageStore::class, $rows[GrantUsageStore::class]->class());
        self::assertSame(GrantHooks::class, $rows[GrantHook::class]->class());
        self::assertNull($rows[TenantTree::class]->factory);
        self::assertSame([], $rows[TenantTree::class]->extenders);
        self::assertTrue(AuthorizationServiceProvider::isPackageDefault($app, GrantUsageStore::class));
    }

    /**
     * The class the configuration names is reported as configured, with the
     * lifetime of the key it forwards to.
     *
     * @return void
     */
    public function testAConfiguredClassIsReported(): void
    {
        $row = self::classifyAll(self::registered(['tenant_tree' => ExplodingTenantTree::class]))[TenantTree::class];

        self::assertSame(Origin::CONFIGURED, $row->origin);
        self::assertSame(ExplodingTenantTree::class, $row->class());
        self::assertSame(Lifetime::SCOPED, $row->lifetime);
    }

    /**
     * Naming the default class with a leading backslash or in another case
     * names the default, so the default is bound and reported, not a configured
     * class.
     *
     * @return void
     */
    public function testTheDefaultNamedAnotherWayIsTheDefault(): void
    {
        foreach (['\\' . FlatTenantTree::class, \strtoupper(FlatTenantTree::class)] as $named) {
            $row = self::classifyAll(self::registered(['tenant_tree' => $named]))[TenantTree::class];

            self::assertSame(Origin::PACKAGE_DEFAULT, $row->origin, $named);
            self::assertSame(FlatTenantTree::class, $row->class(), $named);
        }
    }

    /**
     * Return each way a binding is made, with the lifetime it gives.
     *
     * @return iterable<string, array{class-string, string, \SineMacula\Laravel\Authorization\Diagnostics\Enums\Lifetime}>
     */
    public static function bindings(): iterable
    {
        foreach (self::CONTRACTS as $contract) {
            foreach (['bind' => Lifetime::TRANSIENT, 'singleton' => Lifetime::SINGLETON, 'scoped' => Lifetime::SCOPED, 'instance' => Lifetime::INSTANCE] as $kind => $lifetime) {
                yield \class_basename($contract) . " by {$kind}" => [$contract, $kind, $lifetime];
            }
        }
    }

    /**
     * A binding made before the package registered stands, and is reported as
     * earlier, with its class and lifetime.
     *
     * @param  class-string  $contract
     * @param  string  $kind
     * @param  \SineMacula\Laravel\Authorization\Diagnostics\Enums\Lifetime  $lifetime
     * @return void
     */
    #[DataProvider('bindings')]
    public function testAnEarlierBindingIsReported(string $contract, string $kind, Lifetime $lifetime): void
    {
        $row = self::classifyAll(self::registered(before: static fn (Application $app) => self::bind($app, $contract, $kind)))[$contract];

        self::assertSame(Origin::EARLIER_BINDING, $row->origin);
        self::assertSame(ExplodingTenantTree::class, $row->class());
        self::assertSame($lifetime, $row->lifetime);
        self::assertNull($row->factory);
    }

    /**
     * A binding made after the package registered replaces the package's, and
     * is reported as later, with its class and lifetime.
     *
     * @param  class-string  $contract
     * @param  string  $kind
     * @param  \SineMacula\Laravel\Authorization\Diagnostics\Enums\Lifetime  $lifetime
     * @return void
     */
    #[DataProvider('bindings')]
    public function testALaterBindingIsReported(string $contract, string $kind, Lifetime $lifetime): void
    {
        $row = self::classifyAll(self::registered(after: static fn (Application $app) => self::bind($app, $contract, $kind)))[$contract];

        self::assertSame(Origin::LATER_BINDING, $row->origin);
        self::assertSame(ExplodingTenantTree::class, $row->class());
        self::assertSame($lifetime, $row->lifetime);
    }

    /**
     * Return each seam of the matrix.
     *
     * @return iterable<string, array{class-string}>
     */
    public static function contracts(): iterable
    {
        foreach (self::CONTRACTS as $contract) {
            yield \class_basename($contract) => [$contract];
        }
    }

    /**
     * A closure that names no class is custom code whose class is decided at
     * first use, shown by where it is written, before the package registered or
     * after.
     *
     * @param  class-string  $contract
     * @return void
     */
    #[DataProvider('contracts')]
    public function testAnUnknownFactoryIsShownByWhereItIsWritten(string $contract): void
    {
        $line    = __LINE__ + 1;
        $factory = static fn (): object => new ExplodingTenantTree;

        $earlier = self::classifyAll(self::registered(before: static fn (Application $app) => $app->bind($contract, $factory)))[$contract];
        $later   = self::classifyAll(self::registered(after: static fn (Application $app) => $app->bind($contract, $factory)))[$contract];

        self::assertSame(Origin::EARLIER_BINDING, $earlier->origin);
        self::assertSame(Origin::LATER_BINDING, $later->origin);

        foreach ([$earlier, $later] as $row) {
            self::assertNull($row->class());
            self::assertSame(self::FILE . ":{$line}", $row->factory);
            self::assertTrue($row->isDecidedAtFirstUse());
        }
    }

    /**
     * A sibling's adapter, declared with the closure it bound, is reported as
     * the sibling's while that closure is bound, with the lifetime declared for
     * the key it forwards to; once a later binding replaces it, the later
     * binding is reported and the declaration is shown as overridden.
     *
     * @param  class-string  $contract
     * @return void
     */
    #[DataProvider('contracts')]
    public function testASiblingDeclarationStandsUntilOverridden(string $contract): void
    {
        $sibling = static function (Application $app) use ($contract): void {
            $app->scoped("sibling:{$contract}", ExplodingTenantTree::class);

            $binding = static fn (Application $app): mixed => $app->make("sibling:{$contract}");

            $app->bind($contract, $binding);

            Declarations::of($app)->adapter($contract, 'acme/sibling', ExplodingTenantTree::class, Lifetime::SCOPED, $binding);
        };

        $standing   = self::classifyAll(self::registered(before: $sibling))[$contract];
        $overridden = self::classifyAll(self::registered(before: $sibling, after: static fn (Application $app) => $app->singleton($contract, FlatTenantTree::class)))[$contract];

        self::assertSame(Origin::DECLARED, $standing->origin);
        self::assertSame(ExplodingTenantTree::class, $standing->class());
        self::assertSame(Lifetime::SCOPED, $standing->lifetime);
        self::assertSame(
            ['owner' => 'acme/sibling', 'classes' => [ExplodingTenantTree::class], 'decides' => null, 'lifetime' => 'scoped', 'state' => 'standing'],
            $standing->toArray()['declaration'],
        );

        self::assertSame(Origin::LATER_BINDING, $overridden->origin);
        self::assertSame(FlatTenantTree::class, $overridden->class());
        self::assertSame(Lifetime::SINGLETON, $overridden->lifetime);
        self::assertSame('overridden', $overridden->toArray()['declaration']['state'] ?? null);
    }

    /**
     * A declaration naming no closure is shown beside whatever is bound, as
     * unverified.
     *
     * @return void
     */
    public function testADeclarationWithoutItsClosureIsUnverified(): void
    {
        $row = self::classifyAll(self::registered(before: static function (Application $app): void {
            $app->bind(TenantTree::class, ExplodingTenantTree::class);

            Declarations::of($app)->adapter(TenantTree::class, 'acme/sibling', ExplodingTenantTree::class, Lifetime::TRANSIENT);
        }))[TenantTree::class];

        self::assertSame(Origin::EARLIER_BINDING, $row->origin);
        self::assertSame('unverified', $row->toArray()['declaration']['state'] ?? null);
    }

    /**
     * A declared factory shows the set of classes it may build and when it
     * decides, never one class.
     *
     * @return void
     */
    public function testADeclaredFactoryShowsItsClasses(): void
    {
        $row = self::classifyAll(self::registered(after: static function (Application $app): void {
            $binding = static fn (): object => new ExplodingTenantTree;

            $app->bind(TenantTree::class, $binding);

            Declarations::of($app)->factory(
                TenantTree::class,
                'acme/sibling',
                [ExplodingTenantTree::class, FlatTenantTree::class],
                'per tenant, at first use',
                Lifetime::TRANSIENT,
                $binding,
            );
        }))[TenantTree::class];

        self::assertSame(Origin::DECLARED, $row->origin);
        self::assertNull($row->class());
        self::assertSame([ExplodingTenantTree::class, FlatTenantTree::class], $row->classes);
        self::assertSame('per tenant, at first use', $row->toArray()['decides']);
        self::assertNull($row->factory);
        self::assertFalse($row->isDecidedAtFirstUse());
    }

    /**
     * A deferred provider not loaded yet is reported, naming it, and nothing is
     * loaded to report it.
     *
     * @return void
     */
    public function testADeferredProviderNotLoadedIsReported(): void
    {
        DeferredBindingProvider::$objects = [TenantTree::class => new \stdClass];

        $app = self::registered(after: static fn (Application $app) => $app->addDeferredServices([TenantTree::class => DeferredBindingProvider::class]));
        $row = self::classifyAll($app)[TenantTree::class];

        self::assertSame(Origin::DEFERRED, $row->origin);
        self::assertSame(DeferredBindingProvider::class, $row->toArray()['deferred_provider']);
        self::assertTrue($app->isDeferredService(TenantTree::class));
    }

    /**
     * The extenders registered on a seam are shown in order: the package's,
     * which runs the configured grant hooks, by that setting, any other by
     * where it is written.
     *
     * @return void
     */
    public function testTheExtendersAreShownInOrder(): void
    {
        $line = __LINE__ + 1;
        $wrap = static fn (GrantHook $hook): GrantHook => $hook;
        $app  = self::registered(['grant_hooks' => [ExplodingGrantHook::class]], after: static fn (Application $app) => $app->extend(GrantHook::class, $wrap));
        $row  = self::classifyAll($app)[GrantHook::class];

        self::assertSame(['authorization.grant_hooks', self::FILE . ":{$line}"], $row->extenders);
        self::assertSame(Origin::PACKAGE_DEFAULT, $row->origin);
    }

    /**
     * A contract that is an alias of another abstract is reported as one, with
     * the abstract it resolves to.
     *
     * @return void
     */
    public function testAnAliasIsReported(): void
    {
        $row = self::classifyAll(self::registered(after: static fn (Application $app) => $app->alias(ExplodingTenantTree::class, TenantTree::class)))[TenantTree::class];

        self::assertSame(Origin::ALIAS, $row->origin);
        self::assertSame(ExplodingTenantTree::class, $row->class());
        self::assertSame(ExplodingTenantTree::class, $row->toArray()['alias']);
    }

    /**
     * A contract the package never binds is unbound until the application binds
     * it, and is then an external binding; a policy store left null is unbound.
     *
     * @return void
     */
    public function testAContractThePackageNeverBindsIsUnboundOrExternal(): void
    {
        $unbound = self::classifyAll(self::registered());
        $bound   = self::classifyAll(self::registered(after: static fn (Application $app) => $app->bind(ScopeRegistry::class, ExplodingTenantTree::class)));

        self::assertSame(Origin::UNBOUND, $unbound[ScopeRegistry::class]->origin);
        self::assertSame(Origin::UNBOUND, $unbound[PolicyStore::class]->origin);
        self::assertNull($unbound[ScopeRegistry::class]->lifetime);
        self::assertSame(Origin::EXTERNAL, $bound[ScopeRegistry::class]->origin);
        self::assertSame(ExplodingTenantTree::class, $bound[ScopeRegistry::class]->class());
    }

    /**
     * A seam resolved before is shown as previously resolved; one never
     * resolved is not.
     *
     * @return void
     */
    public function testAPreviouslyResolvedSeamIsShownAsSuch(): void
    {
        $app = self::registered();

        $app->make(GrantHook::class);

        $rows = self::classifyAll($app);

        self::assertTrue($rows[GrantHook::class]->binding->previouslyResolved);
        self::assertFalse($rows[TenantTree::class]->binding->previouslyResolved);
    }

    /**
     * Bind the contract to the exploding tenant tree the way given, building
     * nothing.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @param  class-string  $contract
     * @param  string  $kind
     * @return void
     */
    private static function bind(Application $app, string $contract, string $kind): void
    {
        if ($kind === 'instance') {
            $app->instance($contract, (new \ReflectionClass(ExplodingTenantTree::class))->newInstanceWithoutConstructor());

            return;
        }

        match ($kind) {
            'singleton' => $app->singleton($contract, ExplodingTenantTree::class),
            'scoped'    => $app->scoped($contract, ExplodingTenantTree::class),
            default     => $app->bind($contract, ExplodingTenantTree::class),
        };
    }

    /**
     * Return a new application holding the authorization configuration given,
     * with the package registered in it between the two callbacks.
     *
     * @param  array<string, mixed>  $authorization
     * @param  (\Closure(\Illuminate\Foundation\Application): mixed)|null  $before
     * @param  (\Closure(\Illuminate\Foundation\Application): mixed)|null  $after
     * @return \Illuminate\Foundation\Application
     */
    private static function registered(array $authorization = [], ?\Closure $before = null, ?\Closure $after = null): Application
    {
        $app = new Application(\dirname(__DIR__, 3));

        $app->instance('config', new Repository(['authorization' => $authorization]));

        if ($before !== null) {
            $before($app);
        }

        (new AuthorizationServiceProvider($app))->register();

        if ($after !== null) {
            $after($app);
        }

        return $app;
    }

    /**
     * Classify every seam the report lists, checking that nothing was built and
     * that whether each was resolved is unchanged, and return the rows keyed by
     * contract.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return array<string, \SineMacula\Laravel\Authorization\Diagnostics\SeamRow>
     */
    private static function classifyAll(Application $app): array
    {
        $contracts  = Inspector::SEAMS;
        $resolved   = \array_map($app->resolved(...), $contracts);
        $classifier = new SeamClassifier($app, BindingRegistry::of($app), Declarations::of($app), $app->basePath());
        $rows       = [];

        foreach ($contracts as $contract) {
            $rows[$contract] = $classifier->classify($contract);
        }

        self::assertSame($resolved, \array_map($app->resolved(...), $contracts), 'Classifying resolved a seam.');
        self::assertSame(0, Explosions::$count, 'Classifying built a seam.');

        return $rows;
    }
}
