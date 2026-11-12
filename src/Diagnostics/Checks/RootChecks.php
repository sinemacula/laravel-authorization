<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Diagnostics\Checks;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authorization\Config\ConfigBlock;
use SineMacula\Laravel\Authorization\Config\ConfigValidator;
use SineMacula\Laravel\Authorization\Config\GrantHookConfigValidator;
use SineMacula\Laravel\Authorization\Config\ImplementationConfigValidator;
use SineMacula\Laravel\Authorization\Config\NamedEntryConfigValidator;
use SineMacula\Laravel\Authorization\Config\RequirementCheckerConfigValidator;
use SineMacula\Laravel\Authorization\Config\SeamConfigValidator;
use SineMacula\Laravel\Authorization\Config\TableConfigValidator;
use SineMacula\Laravel\Authorization\Config\TableNames;
use SineMacula\Laravel\Authorization\Contracts\PolicyStore;
use SineMacula\Laravel\Authorization\Diagnostics\IssueCollector;
use SineMacula\Laravel\Authorization\Resolvers\RefusingRequirementChecker;

/**
 * The structural checks of the settings at the top of the configuration: the
 * connection, the table prefix and names, the default guard, the log channel,
 * the models, the permission enums and providers, the seams, the application
 * access map and the grant hooks, each setting and each entry on its own.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RootChecks
{
    /**
     * Create a new set of checks.
     *
     * @param  \SineMacula\Laravel\Authorization\Diagnostics\IssueCollector  $collector
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  array<array-key, mixed>  $config
     */
    public function __construct(

        /** What records each issue. */
        private IssueCollector $collector,

        /** The container the configured names are checked against. */
        private Container $container,

        /** The configuration checked. */
        private array $config,
    ) {}

    /**
     * Run the checks.
     *
     * @return void
     */
    public function run(): void
    {
        $container  = $this->container;
        $connection = $this->given('connection', null);
        $channel    = $this->given('log_channel', null);

        $this->collector->verify('authorization.connection', static function () use ($connection, $container): void {
            NamedEntryConfigValidator::connection($connection, $container);
        });
        $this->tables();
        $this->defaults();
        $this->collector->verify('authorization.log_channel', static function () use ($channel, $container): void {
            NamedEntryConfigValidator::logChannel($channel, $container);
        });
        $this->models();
        $this->collector->verifyEntries('authorization.permission_enums', $this->given('permission_enums', []), ConfigValidator::permissionEnum(...));
        $this->collector->verifyEntries('authorization.permission_providers', $this->given('permission_providers', []), ConfigValidator::permissionProvider(...));
        $this->seams();
        $this->collector->verifyEntries('authorization.application_access', $this->given('application_access', []), ConfigValidator::applicationAccess(...));
        $this->grantHooks();
    }

    /**
     * Check the prefix and each table's name, then that no two tables share a
     * name among the names that passed. A name left at its default is checked
     * with the prefix before it, and is skipped when the prefix was refused.
     *
     * @return void
     */
    private function tables(): void
    {
        $keys  = TableConfigValidator::keys();
        $block = $this->collector->block(TableConfigValidator::KEY, $this->given('tables', []), $keys);

        if ($block === null) {
            $this->collector->skipBlock(TableConfigValidator::KEY, $keys);

            return;
        }

        $path   = TableConfigValidator::KEY . '.' . TableNames::PREFIX;
        $given  = ConfigBlock::entry($block, TableNames::PREFIX, '');
        $prefix = \is_string($given) ? $given : '';
        $names  = [];
        $named  = [];

        $isPrefixAccepted = $this->collector->verify($path, static function () use ($given): void {
            TableConfigValidator::prefix($given);
        });

        // Each check refuses under the table's own path, or the prefix's, so
        // the block's path is recorded only for a failure the checks did not
        // foresee.
        foreach (\array_keys(TableConfigValidator::LENGTHS) as $key) {
            $name = ConfigBlock::entry($block, $key, TableNames::defaultName($key));

            if (!$isPrefixAccepted && TableNames::isDefault($key, $name)) {
                $this->collector->skip(TableConfigValidator::KEY . ".{$key}", $path);

                continue;
            }

            $this->collector->verify(TableConfigValidator::KEY, static function () use ($key, $name, $prefix, &$names): void {
                $names[$key] = TableConfigValidator::effective($key, $name, $prefix);
            });
        }

        foreach ($names as $key => $name) {
            $this->collector->verify(TableConfigValidator::KEY, static function () use ($key, $name, &$named): void {
                $named = TableConfigValidator::distinct($key, $name, $named);
            });
        }
    }

    /**
     * Check the `defaults` block and the guard it names.
     *
     * @return void
     */
    private function defaults(): void
    {
        $path  = 'authorization.defaults';
        $block = $this->collector->block($path, $this->given('defaults', []), NamedEntryConfigValidator::DEFAULTS);

        if ($block === null) {
            $this->collector->skipBlock($path, NamedEntryConfigValidator::DEFAULTS);

            return;
        }

        $container = $this->container;
        $guard     = ConfigBlock::entry($block, 'guard', NamedEntryConfigValidator::GUARD);

        $this->collector->verify("{$path}.guard", static function () use ($guard, $container): void {
            NamedEntryConfigValidator::guard($guard, $container);
        });
    }

    /**
     * Check the `models` block and each model it sets.
     *
     * @return void
     */
    private function models(): void
    {
        $path  = 'authorization.models';
        $keys  = \array_keys(ConfigValidator::MODELS);
        $block = $this->collector->block($path, $this->given('models', []), $keys);

        if ($block === null) {
            $this->collector->skipBlock($path, $keys);

            return;
        }

        foreach (\array_intersect_key($block, ConfigValidator::MODELS) as $key => $class) {
            $this->collector->verify("{$path}.{$key}", static function () use ($key, $class): void {
                ConfigValidator::model($key, $class);
            });
        }
    }

    /**
     * Check each seam setting on its own; a null policy store means none.
     *
     * @return void
     */
    private function seams(): void
    {
        foreach (SeamConfigValidator::SEAMS as $key => [$contract, $default, $required]) {
            $value = $this->given($key, $default);

            $this->collector->verify("authorization.{$key}", static function () use ($key, $value, $contract, $required): void {
                ImplementationConfigValidator::validate("authorization.{$key}", $value, $contract, $required);
            });
        }

        $checker = $this->given('requirement_checker', RefusingRequirementChecker::class);
        $store   = $this->given('policy_store', null);

        $this->collector->verify(RequirementCheckerConfigValidator::KEY, static function () use ($checker): void {
            RequirementCheckerConfigValidator::validate($checker);
        });
        $this->collector->verify('authorization.policy_store', static function () use ($store): void {
            if ($store === null) {
                return;
            }

            ImplementationConfigValidator::validate('authorization.policy_store', $store, PolicyStore::class, '');
        });
    }

    /**
     * Check that `grant_hooks` is a list, then each hook it lists, a hook
     * listed before counting as seen only once it passed.
     *
     * @return void
     */
    private function grantHooks(): void
    {
        $hooks = $this->given('grant_hooks', []);

        $isList = $this->collector->verify(GrantHookConfigValidator::KEY, static function () use ($hooks): void {
            if (\is_array($hooks) && \array_is_list($hooks)) {
                return;
            }

            GrantHookConfigValidator::validate($hooks);
        });

        if (!$isList || !\is_array($hooks)) {
            return;
        }

        $seen = [];

        foreach ($hooks as $index => $class) {
            $this->collector->verify(GrantHookConfigValidator::KEY . ".{$index}", static function () use ($index, $class, &$seen): void {
                $seen = GrantHookConfigValidator::entry((int) $index, $class, $seen);
            });
        }
    }

    /**
     * Return the value the configuration sets for the key, or the default when
     * it leaves the key out.
     *
     * @param  string  $key
     * @param  mixed  $default
     * @return mixed
     */
    private function given(string $key, mixed $default): mixed
    {
        return ConfigBlock::entry($this->config, $key, $default);
    }
}
