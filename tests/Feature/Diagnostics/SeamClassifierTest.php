<?php

declare(strict_types = 1);

namespace Tests\Feature\Diagnostics;

use Illuminate\Config\Repository;
use Illuminate\Container\Container;
use Illuminate\Foundation\Application;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Authorization\Console\Support\SeamText;
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
use SineMacula\Laravel\Authorization\Diagnostics\GrantHookOrder;
use SineMacula\Laravel\Authorization\Diagnostics\Inspector;
use SineMacula\Laravel\Authorization\Diagnostics\SeamClassifier;
use SineMacula\Laravel\Authorization\Diagnostics\SeamRow;
use SineMacula\Laravel\Authorization\Hooks\GrantHooks;
use SineMacula\Laravel\Authorization\Hooks\ListedGrantHooks;
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
        self::assertNull($row->lifetime);

        $scoped = self::classifyAll(self::registered(after: static function (Application $app): void {
            $app->scoped(ExplodingTenantTree::class);
            $app->alias(ExplodingTenantTree::class, TenantTree::class);
        }))[TenantTree::class];

        self::assertSame(Origin::ALIAS, $scoped->origin);
        self::assertSame(Lifetime::SCOPED, $scoped->lifetime);
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
     * A singleton or scoped binding resolved before the package registered is
     * still the earlier binding, shown by the class of what it built.
     *
     * @param  class-string  $contract
     * @return void
     */
    #[DataProvider('contracts')]
    public function testAnEarlierSharedBindingResolvedBeforeRegistrationIsEarlier(string $contract): void
    {
        foreach (['singleton' => Lifetime::SINGLETON, 'scoped' => Lifetime::SCOPED] as $kind => $lifetime) {
            $row = self::classifyAll(self::registered(before: static function (Application $app) use ($contract, $kind): void {
                self::share($app, $kind, $contract, static fn (): object => self::unbuilt(ExplodingTenantTree::class));
                $app->make($contract);
            }))[$contract];

            self::assertSame(Origin::EARLIER_BINDING, $row->origin, $kind);
            self::assertSame(ExplodingTenantTree::class, $row->class(), $kind);
            self::assertSame($lifetime, $row->lifetime, $kind);
            self::assertTrue($row->binding->previouslyResolved, $kind);
            self::assertNull($row->factory, $kind);
        }
    }

    /**
     * An instance handed over a shared binding, the package's earlier one or a
     * sibling's declared one, is what the contract resolves to: it is shown by
     * its class, as a later binding, never as the binding under it.
     *
     * @return void
     */
    public function testAnInstanceHandedOverASharedBindingIsShown(): void
    {
        $handed    = static fn (Application $app) => $app->instance(TenantTree::class, new \ArrayObject);
        $declaring = static fn (string $kind): \Closure => static function (Application $app) use ($kind): void {
            $binding  = static fn (): object => self::unbuilt(ExplodingTenantTree::class);
            $lifetime = $kind === 'singleton' ? Lifetime::SINGLETON : Lifetime::SCOPED;

            self::share($app, $kind, TenantTree::class, $binding);

            Declarations::of($app)->adapter(TenantTree::class, 'acme/sibling', ExplodingTenantTree::class, $lifetime, $binding);
        };

        $rows = [
            'earlier singleton'  => self::registered(before: static fn (Application $app) => $app->singleton(TenantTree::class, ExplodingTenantTree::class), after: $handed),
            'declared singleton' => self::registered(before: $declaring('singleton'), after: $handed),
            'declared scoped'    => self::registered(before: $declaring('scoped'), after: $handed),
        ];

        foreach ($rows as $case => $app) {
            $row = self::classifyAll($app)[TenantTree::class];

            self::assertSame(Origin::LATER_BINDING, $row->origin, $case);
            self::assertSame(\get_class($app->make(TenantTree::class)), $row->class(), $case);
            self::assertSame(Lifetime::INSTANCE, $row->lifetime, $case);
            self::assertFalse($row->binding->previouslyResolved, $case);
            self::assertStringNotContainsString('previously resolved', SeamText::line($row), $case);
        }

        self::assertSame('instance_over_it', self::classifyAll($rows['declared scoped'])[TenantTree::class]->toArray()['declaration']['state'] ?? null);
    }

    /**
     * The grant hook held as an instance before the package registered, which
     * the configured grant hooks wrapped at once, is still the earlier binding,
     * shown by the hook it wraps, with the configured hooks applied to it; one
     * a binding built before is too.
     *
     * @return void
     */
    public function testAnEarlierGrantHookWrappedAtOnceIsEarlier(): void
    {
        $hooks   = ['grant_hooks' => [ExplodingGrantHook::class]];
        $befores = [
            'instance'  => static fn (Application $app) => $app->instance(GrantHook::class, self::unbuilt(ExplodingGrantHook::class)),
            'singleton' => static function (Application $app): void {
                $app->singleton(GrantHook::class, static fn (): object => self::unbuilt(ExplodingGrantHook::class));
                $app->make(GrantHook::class);
            },
        ];

        foreach ($befores as $kind => $before) {
            $row   = self::classifyAll(self::registered($hooks, before: $before))[GrantHook::class];
            $order = GrantHookOrder::of($hooks['grant_hooks'], $row);

            self::assertSame(Origin::EARLIER_BINDING, $row->origin, $kind);
            self::assertSame(ExplodingGrantHook::class, $row->class(), $kind);
            self::assertSame([SeamClassifier::APPLIED], $row->extenders, $kind);
            self::assertSame(ExplodingGrantHook::class, $order[1]['class'] ?? null, $kind);
            self::assertTrue($order[1]['runs'], $kind);
        }

        $unwrapped = self::classifyAll(self::registered($hooks, before: static fn (Application $app) => $app->instance(GrantHook::class, new \stdClass)))[GrantHook::class];

        self::assertSame(Origin::EARLIER_BINDING, $unwrapped->origin);
        self::assertSame(\stdClass::class, $unwrapped->class());
        self::assertSame([], $unwrapped->extenders);
    }

    /**
     * A deferred provider known as the package registered, which the package
     * left the contract to, is shown as that provider once it has loaded.
     *
     * @return void
     */
    public function testALoadedDeferredProviderIsNotALaterBinding(): void
    {
        DeferredBindingProvider::$objects = [TenantTree::class => new \stdClass];

        $app = self::registered(
            before: static fn (Application $app) => $app->addDeferredServices([TenantTree::class => DeferredBindingProvider::class]),
            after: static fn (Application $app) => $app->loadDeferredProvider(TenantTree::class),
        );
        $row = self::classifyAll($app)[TenantTree::class];

        self::assertSame(Origin::DEFERRED_LOADED, $row->origin);
        self::assertSame(DeferredBindingProvider::class, $row->source);
        self::assertNull($row->toArray()['deferred_provider']);
        self::assertSame(DeferredBindingProvider::class, $row->toArray()['deferred_provider_at_registration']);
        self::assertNull($row->class());
        self::assertSame('tests/Feature/Stubs/DeferredBindingProvider.php:34', $row->factory);

        $later = self::classifyAll(self::registered(
            ['tenant_tree' => ExplodingTenantTree::class],
            before: static fn (Application $app) => $app->addDeferredServices([TenantTree::class => DeferredBindingProvider::class]),
            after: static fn (Application $app) => $app->bind(TenantTree::class, FlatTenantTree::class),
        ))[TenantTree::class];

        self::assertSame(Origin::LATER_BINDING, $later->origin);
    }

    /**
     * A contract bound by class name while a deferred provider not loaded yet
     * provides it builds no class known yet.
     *
     * @return void
     */
    public function testADeferredContractBuildsNoClassKnownYet(): void
    {
        DeferredBindingProvider::$objects = [TenantTree::class => new \stdClass];

        $row = self::classifyAll(self::registered(after: static function (Application $app): void {
            $app->bind(TenantTree::class, ExplodingTenantTree::class);
            $app->addDeferredServices([TenantTree::class => DeferredBindingProvider::class]);
        }))[TenantTree::class];

        self::assertSame(Origin::DEFERRED, $row->origin);
        self::assertSame([], $row->classes);
        self::assertNull($row->class());
    }

    /**
     * A binding made with a class name lives as long as the class's own
     * binding, followed through an alias, and a loop of such bindings ends; the
     * package's default lives as long as the configured class's binding when
     * that outlives the scoped key.
     *
     * @return void
     */
    public function testAForwardingBindingLivesAsLongAsItsTarget(): void
    {
        $cases = [
            'class binding' => [Lifetime::SINGLETON, static function (Application $app): void {
                $app->singleton(FlatTenantTree::class);
                $app->bind(TenantTree::class, FlatTenantTree::class);
            }],
            'aliased class binding' => [Lifetime::SINGLETON, static function (Application $app): void {
                $app->singleton(FlatTenantTree::class);
                $app->alias(FlatTenantTree::class, 'flat');
                $app->bind(TenantTree::class, 'flat');
            }],
            'loop' => [Lifetime::SCOPED, static function (Application $app): void {
                $app->scoped('tree', TenantTree::class);
                $app->bind(TenantTree::class, 'tree');
            }],
            'unbound class' => [Lifetime::TRANSIENT, static fn (Application $app) => $app->bind(TenantTree::class, FlatTenantTree::class)],
        ];

        foreach ($cases as $case => [$lifetime, $after]) {
            $row = self::classifyAll(self::registered(after: $after))[TenantTree::class];

            self::assertSame(Origin::LATER_BINDING, $row->origin, $case);
            self::assertSame($lifetime, $row->lifetime, $case);
        }

        $configured = self::classifyAll(self::registered(
            ['tenant_tree' => ExplodingTenantTree::class],
            after: static fn (Application $app) => $app->singleton(ExplodingTenantTree::class),
        ))[TenantTree::class];

        self::assertSame(Origin::CONFIGURED, $configured->origin);
        self::assertSame(Lifetime::SINGLETON, $configured->lifetime);
    }

    /**
     * A closure is shown by where it is written whatever it captures and
     * whatever class it is declared in, and an extender is the configured grant
     * hooks' only when it is the package's own.
     *
     * @return void
     */
    public function testClosuresAreShownByWhereTheyAreWritten(): void
    {
        [$captures, $capturesLine] = self::capturing();

        $unscopedLine  = __LINE__ + 1;
        $unscoped      = \Closure::bind(static fn (): object => new \stdClass, null, null);
        $containerLine = __LINE__ + 1;
        $container     = \Closure::bind(static fn (): object => new \stdClass, null, Container::class);
        $hooksLine     = __LINE__ + 1;
        $hooks         = \Closure::bind(static fn (mixed $hook): mixed => $hook, null, ListedGrantHooks::class);

        self::assertInstanceOf(\Closure::class, $unscoped);
        self::assertInstanceOf(\Closure::class, $container);
        self::assertInstanceOf(\Closure::class, $hooks);

        $bindings = ['captures' => [$captures, $capturesLine], 'unscoped' => [$unscoped, $unscopedLine], 'container' => [$container, $containerLine]];

        foreach ($bindings as $case => [$closure, $line]) {
            $row = self::classifyAll(self::registered(after: static fn (Application $app) => $app->bind(TenantTree::class, $closure)))[TenantTree::class];

            self::assertNull($row->class(), $case);
            self::assertSame(self::FILE . ":{$line}", $row->factory, $case);
        }

        $app = self::registered(after: static function (Application $app) use ($unscoped, $hooks): void {
            $app->extend(GrantHook::class, $unscoped);
            $app->extend(GrantHook::class, $hooks);
        });

        self::assertSame([self::FILE . ":{$unscopedLine}", self::FILE . ":{$hooksLine}"], self::classifyAll($app)[GrantHook::class]->extenders);
    }

    /**
     * The file a closure is written in is shown relative to the base path,
     * whether or not the base path ends in a separator, and whole when it lies
     * outside the base path, or the base path is the root.
     *
     * @return void
     */
    public function testTheFileIsShownRelativeToTheBasePath(): void
    {
        $line    = __LINE__ + 1;
        $factory = static fn (): object => new \stdClass;
        $app     = self::registered(after: static fn (Application $app) => $app->bind(TenantTree::class, $factory));
        $whole   = __FILE__ . ":{$line}";
        $paths   = [$app->basePath() . '/' => self::FILE . ":{$line}", '/nonexistent' => $whole, '/' => $whole, '' => $whole];

        foreach ($paths as $basePath => $expected) {
            $classifier = new SeamClassifier($app, BindingRegistry::of($app), Declarations::of($app), $basePath === '' ? null : $basePath);

            self::assertSame($expected, $classifier->classify(TenantTree::class)->factory, $basePath);
        }
    }

    /**
     * Return a closure that captures a class name in a variable named as the
     * one Laravel's own closures hold, though it is not Laravel's, and the line
     * it is written on.
     *
     * @return array{\Closure(): string, int}
     */
    private static function capturing(): array
    {
        $concrete = ExplodingTenantTree::class;

        return [static fn (): string => $concrete, __LINE__];
    }

    /**
     * Bind the contract to the closure as a singleton or scoped, as given.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @param  string  $kind
     * @param  string  $contract
     * @param  \Closure(): object  $concrete
     * @return void
     */
    private static function share(Application $app, string $kind, string $contract, \Closure $concrete): void
    {
        if ($kind === 'singleton') {
            $app->singleton($contract, $concrete);

            return;
        }

        $app->scoped($contract, $concrete);
    }

    /**
     * Return an object of the class without building it, so nothing explodes.
     *
     * @param  class-string  $class
     * @return object
     */
    private static function unbuilt(string $class): object
    {
        return (new \ReflectionClass($class))->newInstanceWithoutConstructor();
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
            $app->instance($contract, self::unbuilt(ExplodingTenantTree::class));

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
     * with the package registered in it between the two callbacks, then booted,
     * which binds the classes the configuration names and extends the grant
     * hook.
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

        $app->boot();

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
