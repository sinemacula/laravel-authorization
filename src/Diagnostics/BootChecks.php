<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Diagnostics;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authorization\Config\AttributeConfigValidator;
use SineMacula\Laravel\Authorization\Config\CacheConfigValidator;
use SineMacula\Laravel\Authorization\Config\ConfigBlock;
use SineMacula\Laravel\Authorization\Config\ContextConfigValidator;
use SineMacula\Laravel\Authorization\Config\EventConfigValidator;
use SineMacula\Laravel\Authorization\Config\SessionConfigValidator;
use SineMacula\Laravel\Authorization\Contracts\AuthenticationContext;

/**
 * Run the checks the boot runs by building what the configuration names, each
 * on its own, recording what each found and its outcome instead of throwing the
 * first refusal.
 *
 * They are the checks the structural check leaves to the boot: the namespaces
 * the authentication context and the context sources supply, what the attribute
 * providers declare, whether each session scope covers a declared permission
 * and whether each sensitive action is declared, which build the action
 * catalogue, and the cache store. Each runs the boot's own check of its block,
 * which builds what it names through the container, and never through an
 * operation of the package's. A check with nothing to build, a store, scope or
 * sensitive action the configuration does not name, does not run.
 *
 * They run only on a configuration the structural check found nothing wrong
 * with, as each relies on the shape that check confirmed. A failure keeps the
 * exception's class alone, never its message: a refusal is recorded as it
 * states itself, anything else as `internal`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class BootChecks
{
    /** @var string The path of the context sources, whose check builds them and the authentication context. */
    public const string CONTEXT = 'authorization.context.sources';

    /** @var list<string> The paths of the attribute providers, which one check builds together. */
    public const array ATTRIBUTES = ['authorization.attributes.resources', 'authorization.attributes.subjects'];

    /** @var string The path of the cache store, whose check resolves it. */
    public const string CACHE = CacheConfigValidator::KEY . '.store';

    /**
     * Create a new set of checks.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The container what the configuration names is built through. */
        private Container $container,
    ) {}

    /**
     * Return the outcome of each check as none ran, as when the structural
     * check found an issue.
     *
     * @return list<\SineMacula\Laravel\Authorization\Diagnostics\BootCheck>
     */
    public static function notRun(): array
    {
        return \array_map(BootCheck::notRun(...), self::paths());
    }

    /**
     * Run each check on the configuration given, which the structural check
     * found nothing wrong with, and return the outcome of each, by the path of
     * its setting, with every issue found.
     *
     * @param  array<array-key, mixed>  $config
     * @return array{list<\SineMacula\Laravel\Authorization\Diagnostics\BootCheck>, list<\SineMacula\Laravel\Authorization\Diagnostics\ConfigIssue>}
     */
    public function run(array $config): array
    {
        $collector = new IssueCollector;
        $container = $this->container;
        $block     = static fn (string $key): array => self::block($config, $key);

        $context    = $block('context');
        $attributes = $block('attributes');
        $session    = $block('session');
        $cache      = $block('cache');
        $events     = $block('events');
        $store      = ConfigBlock::entry($cache, 'store', null);

        $hasAttributes = ConfigBlock::entry($attributes, 'resources', []) !== [] || ConfigBlock::entry($attributes, 'subjects', []) !== [];
        $hasContext    = ConfigBlock::entry($context, 'sources', [])      !== [] || $container->bound(AuthenticationContext::class);
        $hasScopes     = ConfigBlock::entry($session, 'scopes', [])       !== [];
        $hasSensitive  = self::sensitiveActions($events)                  !== [];
        $attributed    = self::check($collector, self::ATTRIBUTES[0], $hasAttributes, static fn () => AttributeConfigValidator::validate($attributes, $container));

        $checks = [
            self::check($collector, self::CONTEXT, $hasContext, static fn () => ContextConfigValidator::validate($context, $container)),
            $attributed,
            new BootCheck(self::ATTRIBUTES[1], $attributed->outcome, $attributed->exception),
            self::check($collector, SessionConfigValidator::SCOPES, $hasScopes, static fn () => SessionConfigValidator::validate($session, $container)),
            self::check($collector, self::CACHE, $store !== null && $container->bound('cache'), static fn () => CacheConfigValidator::validate($cache, $container)),
            self::check($collector, EventConfigValidator::SENSITIVE_ACTIONS, $hasSensitive, static fn () => EventConfigValidator::validate($events, $container)),
        ];

        return [$checks, $collector->findings()->issues];
    }

    /**
     * Return the path of the setting of each check, in the order they run.
     *
     * @return list<string>
     */
    public static function paths(): array
    {
        return [self::CONTEXT, ...self::ATTRIBUTES, SessionConfigValidator::SCOPES, self::CACHE, EventConfigValidator::SENSITIVE_ACTIONS];
    }

    /**
     * Run the check when it has something to build, recording what it found,
     * and return its outcome.
     *
     * @param  \SineMacula\Laravel\Authorization\Diagnostics\IssueCollector  $collector
     * @param  string  $path
     * @param  bool  $applies
     * @param  \Closure(): mixed  $check
     * @return \SineMacula\Laravel\Authorization\Diagnostics\BootCheck
     */
    private static function check(IssueCollector $collector, string $path, bool $applies, \Closure $check): BootCheck
    {
        return $applies ? BootCheck::ran($path, $collector->attempt($path, $check)) : BootCheck::notRun($path);
    }

    /**
     * Return the sensitive actions the events block sets, none when it sets
     * none.
     *
     * @param  array<array-key, mixed>  $events
     * @return mixed
     */
    private static function sensitiveActions(array $events): mixed
    {
        $decisions = ConfigBlock::entry($events, 'decisions', []);

        return \is_array($decisions) ? ConfigBlock::entry($decisions, 'sensitive_actions', []) : [];
    }

    /**
     * Return the block of the configuration under the key, none when it sets
     * none.
     *
     * @param  array<array-key, mixed>  $config
     * @param  string  $key
     * @return array<array-key, mixed>
     */
    private static function block(array $config, string $key): array
    {
        $block = ConfigBlock::entry($config, $key, []);

        return \is_array($block) ? $block : [];
    }
}
