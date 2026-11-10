<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Diagnostics\Checks;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authorization\Config\AdministrationConfigValidator;
use SineMacula\Laravel\Authorization\Config\BulkConfigValidator;
use SineMacula\Laravel\Authorization\Config\CacheConfigValidator;
use SineMacula\Laravel\Authorization\Config\ConfigBlock;
use SineMacula\Laravel\Authorization\Config\IntegerSetting;
use SineMacula\Laravel\Authorization\Config\NamedEntryConfigValidator;
use SineMacula\Laravel\Authorization\Config\PolicyConfigValidator;
use SineMacula\Laravel\Authorization\Config\QueryScopingConfigValidator;
use SineMacula\Laravel\Authorization\Config\ReviewConfigValidator;
use SineMacula\Laravel\Authorization\Config\SwitchConfigValidator;
use SineMacula\Laravel\Authorization\Config\UsageConfigValidator;
use SineMacula\Laravel\Authorization\Diagnostics\IssueCollector;
use SineMacula\Laravel\Authorization\Evaluation\PolicyLimits;

/**
 * The structural checks of the blocks of plain settings: the switches, the
 * cache, the policy limits, the limits of query scoping, bulk checks,
 * administration and reviews, and grant usage tracking, each setting on its
 * own.
 *
 * The cache store is checked by name only; that it resolves through the cache
 * manager, which builds it, was checked as the application booted.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class BlockChecks
{
    /** @var array<string, array<string, int>> The blocks of whole numbers, each setting mapped to the least it allows. */
    private const array WHOLE_NUMBERS = [
        QueryScopingConfigValidator::KEY   => ['max_anchors' => 1, 'max_scopes' => 1, 'max_attachments' => 1],
        BulkConfigValidator::KEY           => ['chunk_size' => 1],
        AdministrationConfigValidator::KEY => ['max_impact' => 1, 'retries' => 0],
        ReviewConfigValidator::KEY         => ['limit' => 1],
    ];

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
        foreach (SwitchConfigValidator::SWITCHES as $switch) {
            $this->switch($switch);
        }

        $this->cache();
        $this->policies();

        foreach (self::WHOLE_NUMBERS as $path => $settings) {
            $this->wholeNumbers($path, $this->blockOf($path), $settings);
        }

        $this->usage();
    }

    /**
     * Check the switch's block and its `enabled` setting.
     *
     * @param  string  $switch
     * @return void
     */
    private function switch(string $switch): void
    {
        $path  = "authorization.{$switch}";
        $block = $this->read($path, $this->blockOf($path), SwitchConfigValidator::KEYS);

        if ($block === null) {
            return;
        }

        $this->collector->verify("{$path}.enabled", static fn (): bool => SwitchConfigValidator::enabled($switch, $block));
    }

    /**
     * Check the cache block: the store's name, the lifetime and the prefix. A
     * store named is marked as checked at boot, where it was resolved.
     *
     * @return void
     */
    private function cache(): void
    {
        $block = $this->read(CacheConfigValidator::KEY, $this->blockOf(CacheConfigValidator::KEY), CacheConfigValidator::SETTINGS);

        if ($block === null) {
            return;
        }

        $store  = ConfigBlock::entry($block, 'store', null);
        $ttl    = ConfigBlock::entry($block, 'ttl', CacheConfigValidator::TTL);
        $prefix = ConfigBlock::entry($block, 'prefix', CacheConfigValidator::PREFIX);
        $named  = $this->collector->verify(CacheConfigValidator::KEY . '.store', static fn (): ?string => CacheConfigValidator::storeName($store));

        if ($named && $store !== null) {
            $this->collector->checkedAtBoot(CacheConfigValidator::KEY . '.store');
        }

        $this->collector->verify(CacheConfigValidator::KEY . '.ttl', static fn (): int => CacheConfigValidator::ttl($ttl));
        $this->collector->verify(CacheConfigValidator::KEY . '.prefix', static fn (): string => CacheConfigValidator::prefix($prefix));
    }

    /**
     * Check the policies block and each limit it sets.
     *
     * @return void
     */
    private function policies(): void
    {
        $block = $this->read(PolicyConfigValidator::KEY, $this->blockOf(PolicyConfigValidator::KEY), PolicyConfigValidator::SETTINGS);

        if ($block === null) {
            return;
        }

        $this->wholeNumbers(PolicyConfigValidator::KEY . '.limits', ConfigBlock::entry($block, 'limits', []), \array_fill_keys(PolicyLimits::KEYS, 1));
    }

    /**
     * Check a block of whole numbers, each setting it sets against the least it
     * allows; a setting left out takes its default.
     *
     * @param  string  $path
     * @param  mixed  $value
     * @param  array<string, int>  $settings
     * @return void
     */
    private function wholeNumbers(string $path, mixed $value, array $settings): void
    {
        $block = $this->read($path, $value, \array_keys($settings));

        foreach (\array_intersect_key($block ?? [], $settings) as $key => $number) {
            $least = $settings[$key];

            $this->collector->verify("{$path}.{$key}", static fn (): int => IntegerSetting::require("{$path}.{$key}", $number, $least));
        }
    }

    /**
     * Check the usage block: the switch, the whole numbers and the names, then
     * that the queue connection named is configured, which depends on its name
     * being one.
     *
     * @return void
     */
    private function usage(): void
    {
        $block = $this->read(UsageConfigValidator::KEY, $this->blockOf(UsageConfigValidator::KEY), UsageConfigValidator::SETTINGS);

        if ($block === null) {
            return;
        }

        if (\array_key_exists('enabled', $block)) {
            $this->collector->verify(UsageConfigValidator::KEY . '.enabled', static fn (): bool => UsageConfigValidator::enabled($block['enabled']));
        }

        foreach (\array_intersect_key($block, UsageConfigValidator::WHOLE) as $setting => $value) {
            $this->collector->verify(UsageConfigValidator::KEY . ".{$setting}", static fn (): int => UsageConfigValidator::whole($setting, $value));
        }

        $connection = ConfigBlock::entry($block, 'connection', null);
        $queue      = ConfigBlock::entry($block, 'queue', null);
        $container  = $this->container;

        $named = $this->collector->verify(UsageConfigValidator::KEY . '.connection', static fn (): ?string => UsageConfigValidator::name('connection', $connection));

        $this->collector->verify(UsageConfigValidator::KEY . '.queue', static fn (): ?string => UsageConfigValidator::name('queue', $queue));

        if (!$named) {
            return;
        }

        $this->collector->verify(UsageConfigValidator::KEY . '.connection', static function () use ($connection, $container): void {
            NamedEntryConfigValidator::queueConnection($connection, $container);
        });
    }

    /**
     * Return the block under the path, refused when it is not an array, each
     * setting it defines then skipped, null in that case.
     *
     * @param  string  $path
     * @param  mixed  $value
     * @param  list<string>  $keys
     * @return array<array-key, mixed>|null
     */
    private function read(string $path, mixed $value, array $keys): ?array
    {
        $block = $this->collector->block($path, $value, $keys);

        if ($block === null) {
            $this->collector->skipBlock($path, $keys);
        }

        return $block;
    }

    /**
     * Return the value the configuration sets for the block under the path, an
     * empty block when it leaves it out.
     *
     * @param  string  $path
     * @return mixed
     */
    private function blockOf(string $path): mixed
    {
        return ConfigBlock::entry($this->config, \substr($path, \strlen('authorization.')), []);
    }
}
