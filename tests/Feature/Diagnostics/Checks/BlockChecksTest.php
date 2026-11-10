<?php

declare(strict_types = 1);

namespace Tests\Feature\Diagnostics\Checks;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Diagnostics\Checks\BlockChecks;
use SineMacula\Laravel\Authorization\Diagnostics\ConfigFindings;
use SineMacula\Laravel\Authorization\Diagnostics\ConfigIssue;
use SineMacula\Laravel\Authorization\Diagnostics\IssueCollector;
use Tests\TestCase;

/**
 * Feature tests for the structural checks of the blocks of plain settings, each
 * setting on its own.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(BlockChecks::class)]
final class BlockChecksTest extends TestCase
{
    /**
     * Each setting of each block is checked on its own, so every refused one is
     * listed.
     *
     * @return void
     */
    public function testEverySettingIsCheckedOnItsOwn(): void
    {
        self::assertSame([
            ['authorization.gate.enabled', 'invalid_type'],
            ['authorization.rank', 'invalid_type'],
            ['authorization.rank.enabled', 'skipped'],
            ['authorization.cache.store', 'invalid_type'],
            ['authorization.cache.prefix', 'invalid_type'],
            ['authorization.policies.limits.pages', 'unknown_key'],
            ['authorization.policies.limits.statements', 'out_of_range'],
            ['authorization.query_scoping.max_scopes', 'invalid_type'],
            ['authorization.administration.retries', 'out_of_range'],
            ['authorization.reviews.limit', 'out_of_range'],
            ['authorization.usage.interval', 'out_of_range'],
            ['authorization.usage.queue', 'invalid_type'],
        ], self::pathsAndCodes($this->check([
            'gate'           => ['enabled' => 'yes'],
            'rank'           => true,
            'cache'          => ['store' => 3, 'prefix' => ''],
            'policies'       => ['limits' => ['statements' => 0, 'pages' => 3]],
            'query_scoping'  => ['max_scopes' => 'many'],
            'administration' => ['retries' => -1],
            'reviews'        => ['limit' => 0],
            'usage'          => ['interval' => 1, 'queue' => ''],
        ])));
    }

    /**
     * The usage queue connection is checked to be configured only once its name
     * is one, and a cache store named is left to the boot.
     *
     * @return void
     */
    public function testDependentChecksRunOnlyOnceTheirSettingPasses(): void
    {
        $unnamed = $this->check(['usage' => ['connection' => 3]]);
        $unknown = $this->check(['usage' => ['connection' => 'nowhere'], 'cache' => ['store' => 'array']]);

        self::assertSame([['authorization.usage.connection', 'invalid_type']], self::pathsAndCodes($unnamed));
        self::assertSame([['authorization.usage.connection', 'unknown_name']], self::pathsAndCodes($unknown));
        self::assertSame(['authorization.cache.store'], $unknown->checkedAtBoot);
        self::assertSame([], $unnamed->checkedAtBoot);
    }

    /**
     * Check the suite's configuration with the settings given.
     *
     * @param  array<string, mixed>  $settings
     * @return \SineMacula\Laravel\Authorization\Diagnostics\ConfigFindings
     */
    private function check(array $settings): ConfigFindings
    {
        $collector = new IssueCollector;

        (new BlockChecks($collector, $this->container(), [...$this->authorizationConfig(), ...$settings]))->run();

        return $collector->findings();
    }

    /**
     * Return the path and code of each issue found, in order.
     *
     * @param  \SineMacula\Laravel\Authorization\Diagnostics\ConfigFindings  $findings
     * @return list<array{string, string}>
     */
    private static function pathsAndCodes(ConfigFindings $findings): array
    {
        return \array_map(static fn (ConfigIssue $issue): array => [$issue->path, $issue->code->value], $findings->issues);
    }
}
