<?php

declare(strict_types = 1);

namespace Tests\Unit\Console\Support;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Console\Support\SeamText;
use SineMacula\Laravel\Authorization\Diagnostics\CurrentBinding;
use SineMacula\Laravel\Authorization\Diagnostics\Declaration;
use SineMacula\Laravel\Authorization\Diagnostics\Enums\Lifetime;
use SineMacula\Laravel\Authorization\Diagnostics\Enums\Origin;
use SineMacula\Laravel\Authorization\Diagnostics\SeamRecord;
use SineMacula\Laravel\Authorization\Diagnostics\SeamRow;

/**
 * Unit tests for a seam as `authorization:check` prints it as text.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SeamText::class)]
final class SeamTextTest extends TestCase
{
    /** @var string A contract of the package, shown by its short name. */
    private const string CONTRACT = 'SineMacula\Laravel\Authorization\Contracts\TenantTree';

    /** @var string How a later binding is told. */
    private const string LATER = 'bound after the package registered, over its binding';

    /** @var string How an earlier binding is told. */
    private const string EARLIER = 'bound before the package registered, which left it standing';

    /**
     * Each origin is told in words, naming the setting, the owner, the deferred
     * provider or the alias where it has one.
     *
     * @return void
     */
    public function testEachOriginIsTold(): void
    {
        $binding = static fn (): mixed => null;
        $record  = new SeamRecord(self::CONTRACT, $binding, null, 'App\Tree', 'authorization.tenant_tree', true, null, null, null, null);
        $owned   = new Declaration(self::CONTRACT, 'acme/sibling', ['Acme\Tree'], null, Lifetime::SCOPED, $binding);
        $alias   = 'tenancy.tree';
        $sibling = self::row(Origin::DECLARED, $owned->classes, declaration: $owned, concrete: $binding, source: $owned->owner);
        $lines   = [
            'configured in authorization.tenant_tree; App\Tree; scoped'  => self::row(Origin::CONFIGURED, ['App\Tree'], record: $record, source: $record->configKey),
            'declared by acme/sibling; Acme\Tree; scoped'                => $sibling,
            'deferred provider Acme\Provider, not loaded yet'            => self::row(Origin::DEFERRED, [], deferred: 'Acme\Provider', lifetime: null, source: 'Acme\Provider'),
            'deferred provider Acme\Provider (loaded); App\Tree; scoped' => self::row(Origin::DEFERRED_LOADED, ['App\Tree'], source: 'Acme\Provider'),
            'alias of tenancy.tree; tenancy.tree; singleton'             => self::row(Origin::ALIAS, [$alias], lifetime: Lifetime::SINGLETON, alias: $alias, source: $alias),
            self::EARLIER . '; App\Tree; scoped'                         => self::row(Origin::EARLIER_BINDING, ['App\Tree']),
            'package default; App\Tree; scoped'                          => self::row(Origin::PACKAGE_DEFAULT, ['App\Tree']),
            'not bound; none'                                            => self::row(Origin::UNBOUND, [], lifetime: null),
        ];

        foreach ($lines as $line => $row) {
            self::assertSame("[seam TenantTree] {$line}", SeamText::line($row));
        }

        self::assertSame(
            '[seam Acme\Contracts\Thing] bound outside the package; Acme\Thing; scoped',
            SeamText::line(self::row(Origin::EXTERNAL, ['Acme\Thing'], contract: 'Acme\Contracts\Thing')),
        );
    }

    /**
     * A declared factory shows the classes it may build and when it decides;
     * custom code is shown by where it is written, decided at first use.
     *
     * @return void
     */
    public function testWhatTheSeamBuildsIsShown(): void
    {
        $binding = static fn (): mixed => null;
        $factory = new Declaration(self::CONTRACT, 'acme/sibling', ['Acme\One', 'Acme\Two'], 'per tenant', Lifetime::TRANSIENT, $binding);
        $built   = self::row(Origin::DECLARED, ['Acme\One', 'Acme\Two'], declaration: $factory, concrete: $binding, lifetime: Lifetime::TRANSIENT, source: 'acme/sibling');
        $custom  = self::row(Origin::LATER_BINDING, [], factory: 'app/Tree.php:7', lifetime: Lifetime::TRANSIENT);

        $one    = new Declaration(self::CONTRACT, 'acme/sibling', ['Acme\One'], 'per tenant', Lifetime::TRANSIENT, $binding);
        $chosen = self::row(Origin::DECLARED, ['Acme\One'], lifetime: Lifetime::TRANSIENT, declaration: $one, concrete: $binding, source: 'acme/sibling');

        self::assertSame('[seam TenantTree] declared by acme/sibling; one of Acme\One, Acme\Two, decided per tenant; transient', SeamText::line($built));
        self::assertSame('[seam TenantTree] declared by acme/sibling; one of Acme\One, decided per tenant; transient', SeamText::line($chosen));
        self::assertSame(
            '[seam TenantTree] ' . self::LATER . '; supplied by custom code (app/Tree.php:7); class decided at first use; transient',
            SeamText::line($custom),
        );
    }

    /**
     * The extenders, the history and a declaration that no longer stands are
     * noted after the lifetime.
     *
     * @return void
     */
    public function testTheNotesFollowTheLifetime(): void
    {
        $declared   = static fn (): mixed => null;
        $later      = static fn (): mixed => null;
        $adapter    = new Declaration(self::CONTRACT, 'acme/sibling', ['Acme\Tree'], null, Lifetime::SCOPED, $declared);
        $unproven   = new Declaration(self::CONTRACT, 'acme/sibling', ['Acme\Tree'], null, Lifetime::SCOPED, null);
        $extenders  = ['authorization.grant_hooks', 'app/A.php:3'];
        $extended   = self::row(Origin::LATER_BINDING, ['App\Tree'], extenders: $extenders, resolved: true, declaration: $adapter, concrete: $later);
        $unverified = self::row(Origin::EARLIER_BINDING, ['Acme\Tree'], declaration: $unproven, concrete: $later);
        $instance   = self::row(Origin::EARLIER_BINDING, ['Acme\Tree'], declaration: $adapter, concrete: $declared, lifetime: Lifetime::INSTANCE);

        self::assertSame(
            '[seam TenantTree] ' . self::LATER . '; App\Tree; scoped; registered extenders: authorization.grant_hooks, app/A.php:3; previously resolved; '
            . 'declared by acme/sibling as Acme\Tree, but overridden later',
            SeamText::line($extended),
        );
        self::assertSame(
            '[seam TenantTree] ' . self::EARLIER . '; Acme\Tree; scoped; declared by acme/sibling as Acme\Tree, unverified, as it named no binding',
            SeamText::line($unverified),
        );
        self::assertSame(
            '[seam TenantTree] ' . self::EARLIER . '; Acme\Tree; instance; declared by acme/sibling as Acme\Tree, but an instance is bound over it',
            SeamText::line($instance),
        );
    }

    /**
     * Every name is escaped: console markup and control characters never reach
     * the console as such.
     *
     * @return void
     */
    public function testNamesAreEscaped(): void
    {
        self::assertSame(
            '[seam Acme\\\<info\>Thing] bound outside the package; supplied by custom code (app/\<b\>x\u001b.php:1); class decided at first use; scoped',
            SeamText::line(self::row(Origin::EXTERNAL, [], factory: "app/<b>x\e.php:1", contract: 'Acme\<info>Thing')),
        );
    }

    /**
     * Return a row of the seam.
     *
     * @param  \SineMacula\Laravel\Authorization\Diagnostics\Enums\Origin  $origin
     * @param  list<string>  $classes
     * @param  string|null  $factory
     * @param  \SineMacula\Laravel\Authorization\Diagnostics\Enums\Lifetime|null  $lifetime
     * @param  list<string>  $extenders
     * @param  bool  $resolved
     * @param  \SineMacula\Laravel\Authorization\Diagnostics\SeamRecord|null  $record
     * @param  \SineMacula\Laravel\Authorization\Diagnostics\Declaration|null  $declaration
     * @param  (\Closure(): mixed)|null  $concrete
     * @param  string|null  $alias
     * @param  string|null  $deferred
     * @param  string  $contract
     * @param  string|null  $source
     * @return \SineMacula\Laravel\Authorization\Diagnostics\SeamRow
     */
    private static function row(
        Origin $origin,
        array $classes,
        ?string $factory = null,
        ?Lifetime $lifetime = Lifetime::SCOPED,
        array $extenders = [],
        bool $resolved = false,
        ?SeamRecord $record = null,
        ?Declaration $declaration = null,
        ?\Closure $concrete = null,
        ?string $alias = null,
        ?string $deferred = null,
        string $contract = self::CONTRACT,
        ?string $source = null,
    ): SeamRow {
        return new SeamRow(
            $contract,
            $origin,
            $classes,
            $factory,
            $lifetime,
            $extenders,
            new CurrentBinding($concrete, null, $lifetime, $alias, $deferred, $resolved),
            $record,
            $declaration,
            $source,
        );
    }
}
