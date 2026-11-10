<?php

declare(strict_types = 1);

namespace Tests\Feature\Diagnostics\Checks;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Config\CacheConfigValidator;
use SineMacula\Laravel\Authorization\Config\PolicyConfigValidator;
use SineMacula\Laravel\Authorization\Config\UsageConfigValidator;
use SineMacula\Laravel\Authorization\Diagnostics\Checks\BlockChecks;
use SineMacula\Laravel\Authorization\Diagnostics\ConfigFindings;
use SineMacula\Laravel\Authorization\Diagnostics\ConfigIssue;
use SineMacula\Laravel\Authorization\Diagnostics\IssueCollector;
use SineMacula\Laravel\Authorization\Evaluation\PolicyLimits;
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
     * A block that is not an array is refused once, and each setting it holds
     * is skipped, never checked.
     *
     * @return void
     */
    public function testARefusedBlockSkipsItsSettings(): void
    {
        foreach (['cache' => CacheConfigValidator::SETTINGS, 'policies' => PolicyConfigValidator::SETTINGS, 'usage' => UsageConfigValidator::SETTINGS] as $block => $settings) {
            self::assertSame(
                [["authorization.{$block}", 'invalid_type'], ...\array_map(static fn (string $setting): array => ["authorization.{$block}.{$setting}", 'skipped'], $settings)],
                self::pathsAndCodes($this->check([$block => 'x'])),
                $block,
            );
        }
    }

    /**
     * The usage switch is checked on its own.
     *
     * @return void
     */
    public function testTheUsageSwitchIsChecked(): void
    {
        self::assertSame([['authorization.usage.enabled', 'invalid_type']], self::pathsAndCodes($this->check(['usage' => ['enabled' => 'yes']])));
    }

    /**
     * Each whole number passes at the least it allows and is refused below it.
     *
     * @return void
     */
    public function testEachWholeNumberPassesAtItsLeast(): void
    {
        $least = [
            'policies'       => ['limits' => \array_fill_keys(PolicyLimits::KEYS, 1)],
            'query_scoping'  => ['max_anchors' => 1, 'max_scopes' => 1, 'max_attachments' => 1],
            'bulk'           => ['chunk_size' => 1],
            'administration' => ['max_impact' => 1, 'retries' => 0],
            'reviews'        => ['limit' => 1],
        ];

        $below = [
            'policies'       => ['limits' => \array_fill_keys(PolicyLimits::KEYS, 0)],
            'query_scoping'  => ['max_anchors' => 0, 'max_scopes' => 0, 'max_attachments' => 0],
            'bulk'           => ['chunk_size' => 0],
            'administration' => ['max_impact' => 0, 'retries' => -1],
            'reviews'        => ['limit' => 0],
        ];

        self::assertSame([], self::pathsAndCodes($this->check($least)));
        self::assertCount(\count(PolicyLimits::KEYS) + 7, \array_filter(self::pathsAndCodes($this->check($below)), static fn (array $issue): bool => $issue[1] === 'out_of_range'));
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
