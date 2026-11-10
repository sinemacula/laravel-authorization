<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Diagnostics\Checks;

use SineMacula\Laravel\Authorization\Config\AttributeConfigValidator;
use SineMacula\Laravel\Authorization\Config\ConfigBlock;
use SineMacula\Laravel\Authorization\Config\ContextConfigValidator;
use SineMacula\Laravel\Authorization\Config\SessionConfigValidator;
use SineMacula\Laravel\Authorization\Context\AttributeProviders;
use SineMacula\Laravel\Authorization\Diagnostics\IssueCollector;
use SineMacula\Laravel\Authorization\Resolvers\NoSessionPolicy;

/**
 * The structural checks of the settings naming extension code: the context keys
 * and sources, the attribute providers and the session policy source and
 * scopes, each setting and each entry on its own.
 *
 * What builds the code they name is not run: the namespaces the sources and the
 * authentication context supply, what the attribute providers declare and
 * whether each session scope covers a declared permission were checked as the
 * application booted, so a setting naming any is marked `checked_at_boot`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ExtensionChecks
{
    /** @var string The path of the context block. */
    private const string CONTEXT = 'authorization.context';

    /** @var string The path of the attributes block. */
    private const string ATTRIBUTES = 'authorization.attributes';

    /** @var string The path of the session block. */
    private const string SESSION = 'authorization.session';

    /**
     * Create a new set of checks.
     *
     * @param  \SineMacula\Laravel\Authorization\Diagnostics\IssueCollector  $collector
     * @param  array<array-key, mixed>  $config
     */
    public function __construct(

        /** What records each issue. */
        private IssueCollector $collector,

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
        $this->context();
        $this->attributes();
        $this->session();
    }

    /**
     * Check each namespace of `context.keys`, then that the catalogue accepts
     * them, and each class of `context.sources`.
     *
     * @return void
     */
    private function context(): void
    {
        $block = $this->read(self::CONTEXT, ContextConfigValidator::SETTINGS);

        if ($block === null) {
            return;
        }

        $path = self::CONTEXT . '.keys';
        $keys = ConfigBlock::entry($block, 'keys', []);

        if ($this->collector->verifyEntries($path, $keys, ContextConfigValidator::keyEntry(...))) {
            $this->collector->verify($path, static function () use ($keys): void {
                ContextConfigValidator::keys($keys);
            });
        }

        $this->bootChecked(self::CONTEXT . '.sources', ConfigBlock::entry($block, 'sources', []), ContextConfigValidator::source(...));
    }

    /**
     * Check each entry of `attributes.resources` and `attributes.subjects`.
     *
     * @return void
     */
    private function attributes(): void
    {
        $block = $this->read(self::ATTRIBUTES, AttributeConfigValidator::SETTINGS);

        if ($block === null) {
            return;
        }

        foreach (AttributeConfigValidator::NAMESPACES as $key => $namespace) {
            $contract = AttributeProviders::CONTRACTS[$namespace];
            $check    = static function (int|string $type, mixed $class) use ($key, $contract): void {
                AttributeConfigValidator::provider($key, $type, $class, $contract);
            };

            $this->bootChecked(self::ATTRIBUTES . ".{$key}", ConfigBlock::entry($block, $key, []), $check);
        }
    }

    /**
     * Check the session policy source and the shape of the scope map.
     *
     * @return void
     */
    private function session(): void
    {
        $block = $this->read(self::SESSION, SessionConfigValidator::SETTINGS);

        if ($block === null) {
            return;
        }

        $source = ConfigBlock::entry($block, 'source', NoSessionPolicy::class);
        $scopes = ConfigBlock::entry($block, 'scopes', []);

        $this->collector->verify(SessionConfigValidator::SOURCE, static function () use ($source): void {
            SessionConfigValidator::source($source);
        });

        if (!$this->collector->verify(SessionConfigValidator::SCOPES, static fn (): array => SessionConfigValidator::scopeMap($scopes)) || $scopes === []) {
            return;
        }

        $this->collector->checkedAtBoot(SessionConfigValidator::SCOPES);
    }

    /**
     * Check each entry of a list naming extension code, marking the list as
     * checked at boot when it names any and every entry passed.
     *
     * @param  string  $path
     * @param  mixed  $value
     * @param  \Closure(int|string, mixed): mixed  $entry
     * @return void
     */
    private function bootChecked(string $path, mixed $value, \Closure $entry): void
    {
        if (!$this->collector->verifyEntries($path, $value, $entry) || $value === []) {
            return;
        }

        $this->collector->checkedAtBoot($path);
    }

    /**
     * Return the block under the path, refused when it is not an array, each
     * setting it defines then skipped, null in that case.
     *
     * @param  string  $path
     * @param  list<string>  $keys
     * @return array<array-key, mixed>|null
     */
    private function read(string $path, array $keys): ?array
    {
        $value = ConfigBlock::entry($this->config, \substr($path, \strlen('authorization.')), []);
        $block = $this->collector->block($path, $value, $keys);

        if ($block === null) {
            $this->collector->skipBlock($path, $keys);
        }

        return $block;
    }
}
