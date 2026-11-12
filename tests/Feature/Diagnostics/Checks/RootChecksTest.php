<?php

declare(strict_types = 1);

namespace Tests\Feature\Diagnostics\Checks;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Config\TableConfigValidator;
use SineMacula\Laravel\Authorization\Diagnostics\Checks\RootChecks;
use SineMacula\Laravel\Authorization\Diagnostics\ConfigIssue;
use SineMacula\Laravel\Authorization\Diagnostics\IssueCollector;
use SineMacula\Laravel\Authorization\Resolvers\FlatTenantTree;
use Tests\Feature\Stubs\StubPolicyStore;
use Tests\Fixtures\GrantHooks\RecordingGrantHook;
use Tests\TestCase;

/**
 * Feature tests for the structural checks of the settings at the top of the
 * configuration, each setting and each entry on its own.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RootChecks::class)]
final class RootChecksTest extends TestCase
{
    /**
     * Every entry is checked on its own, so each refused entry is listed, and a
     * name two tables share is refused only among the names that passed, once
     * every name is checked.
     *
     * @return void
     */
    public function testEachEntryIsCheckedOnItsOwn(): void
    {
        self::assertSame([
            ['authorization.tables.guardrails', 'out_of_range'],
            ['authorization.tables.permissions', 'duplicate'],
            ['authorization.permission_enums.0', 'invalid_type'],
            ['authorization.permission_enums.1', 'unknown_class'],
            ['authorization.application_access', 'invalid_value'],
            ['authorization.application_access', 'invalid_value'],
        ], $this->issues([
            'tables'             => ['roles' => 'Shared', 'permissions' => 'shared', 'guardrails' => \str_repeat('g', 64)],
            'permission_enums'   => [3, 'Missing\Enum'],
            'application_access' => ['portal' => '', 'admin' => 'admin.access', '' => 'x'],
        ]));
    }

    /**
     * The prefix is checked on its own path; once it is refused, each name left
     * at its default is skipped as depending on it, while each name set
     * explicitly is still checked as it is written.
     *
     * @return void
     */
    public function testARefusedPrefixSkipsTheDefaultNamesAlone(): void
    {
        $skipped = \array_map(
            static fn (string $key): array => ["authorization.tables.{$key}", 'skipped'],
            \array_slice(\array_keys(TableConfigValidator::LENGTHS), 2),
        );

        self::assertSame(
            [['authorization.tables.prefix', 'invalid_value'], ['authorization.tables.permissions', 'invalid_value'], ...$skipped],
            $this->issues(['tables' => ['prefix' => 'App_', 'roles' => 'authz_roles', 'permissions' => 'a b']]),
        );
        $skip = $this->findings(['tables' => ['prefix' => null, 'roles' => 'authz_roles']])[1];

        self::assertSame(['authorization.tables.permissions', 'skipped', 'authorization.tables.prefix'], [$skip->path, $skip->code->value, $skip->dependsOn]);
    }

    /**
     * Once the prefix passes, each name is checked as the package reads it: a
     * default name with the prefix before it, so a name set explicitly that the
     * prefix gives another table is refused as a duplicate.
     *
     * @return void
     */
    public function testAnAcceptedPrefixIsPutBeforeTheDefaultNames(): void
    {
        self::assertSame([], $this->issues(['tables' => ['prefix' => 'app_', 'roles' => 'permissions']]));
        self::assertSame([['authorization.tables.permissions', 'duplicate']], $this->issues(['tables' => ['prefix' => 'x_', 'roles' => 'x_permissions']]));
        self::assertSame([['authorization.tables.prefixes', 'unknown_key']], $this->issues(['tables' => ['prefixes' => 'app_']]));
        self::assertSame([['authorization.tables.break_glass', 'duplicate']], $this->issues(['tables' => ['prefix' => 'x_', 'roles' => 'x_break_glass_activations']]));
    }

    /**
     * Each seam is checked on its own, a null policy store meaning none, and a
     * refused block skips each setting it holds.
     *
     * @return void
     */
    public function testSeamsAndBlocksAreCheckedOnTheirOwn(): void
    {
        self::assertSame([
            ['authorization.defaults', 'invalid_type'],
            ['authorization.defaults.guard', 'skipped'],
            ['authorization.models', 'invalid_type'],
            ['authorization.models.role', 'skipped'],
            ['authorization.models.permission', 'skipped'],
            ['authorization.models.policy', 'skipped'],
            ['authorization.subject_resolver', 'required'],
            ['authorization.tenant_tree', 'not_implemented'],
            ['authorization.requirement_checker', 'invalid_type'],
        ], $this->issues([
            'defaults'            => 'web',
            'models'              => null,
            'subject_resolver'    => null,
            'tenant_tree'         => StubPolicyStore::class,
            'requirement_checker' => 3,
            'policy_store'        => null,
        ]));

        self::assertSame([['authorization.policy_store', 'not_implemented']], $this->issues(['policy_store' => FlatTenantTree::class]));
    }

    /**
     * A grant hooks value that is not a list is refused once; a hook listed
     * twice, whatever its case, is refused as a duplicate.
     *
     * @return void
     */
    public function testTheGrantHooksAreCheckedEachOnItsOwn(): void
    {
        self::assertSame([['authorization.grant_hooks', 'invalid_type']], $this->issues(['grant_hooks' => ['a' => RecordingGrantHook::class]]));
        self::assertSame(
            [['authorization.grant_hooks.1', 'duplicate'], ['authorization.grant_hooks.2', 'unknown_class']],
            $this->issues(['grant_hooks' => [RecordingGrantHook::class, '\\' . \strtoupper(RecordingGrantHook::class), 'Missing\Hook']]),
        );
    }

    /**
     * The names the configuration gives a connection, a log channel and the
     * default guard are each checked against the application's own
     * configuration, and each permission provider and model on its own.
     *
     * @return void
     */
    public function testNamesProvidersAndModelsAreCheckedOnTheirOwn(): void
    {
        self::assertSame([
            ['authorization.connection', 'unknown_name'],
            ['authorization.defaults.guard', 'unknown_name'],
            ['authorization.log_channel', 'unknown_name'],
            ['authorization.models.extra', 'unknown_key'],
            ['authorization.models.role', 'unknown_class'],
            ['authorization.permission_providers.0', 'unknown_class'],
        ], $this->issues([
            'connection'           => 'nowhere',
            'defaults'             => ['guard' => 'nowhere'],
            'log_channel'          => 'nowhere',
            'models'               => ['role' => 'Missing\Model', 'extra' => 'x'],
            'permission_providers' => ['Missing\Provider'],
        ]));
    }

    /**
     * A grant hooks map is refused once, and none of its entries is checked.
     *
     * @return void
     */
    public function testAGrantHooksMapIsRefusedOnce(): void
    {
        self::assertSame([['authorization.grant_hooks', 'invalid_type']], $this->issues(['grant_hooks' => ['a' => 'Missing\Hook']]));
    }

    /**
     * A hook whose check fails in a way the package did not foresee, as when
     * loading its class throws, is recorded under its own entry's path.
     *
     * @return void
     */
    public function testAnUnforeseenFailureIsRecordedUnderTheEntrysPath(): void
    {
        $loader = static function (string $class): void {
            if ($class === 'Throwing\Hook') {
                throw new \RuntimeException('The class could not be loaded.');
            }
        };

        \spl_autoload_register($loader);

        try {
            self::assertSame([['authorization.grant_hooks.0', 'internal']], $this->issues(['grant_hooks' => ['Throwing\Hook']]));
        } finally {
            \spl_autoload_unregister($loader);
        }
    }

    /**
     * Return the path and code of each issue the checks find in the suite's
     * configuration with the settings given.
     *
     * @param  array<string, mixed>  $settings
     * @return list<array{string, string}>
     */
    private function issues(array $settings): array
    {
        return \array_map(static fn (ConfigIssue $issue): array => [$issue->path, $issue->code->value], $this->findings($settings));
    }

    /**
     * Return each issue the checks find in the suite's configuration with the
     * settings given.
     *
     * @param  array<string, mixed>  $settings
     * @return list<\SineMacula\Laravel\Authorization\Diagnostics\ConfigIssue>
     */
    private function findings(array $settings): array
    {
        $collector = new IssueCollector;

        (new RootChecks($collector, $this->container(), [...$this->authorizationConfig(), ...$settings]))->run();

        return $collector->findings()->issues;
    }
}
