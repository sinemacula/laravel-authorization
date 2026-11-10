<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authorization\Administration\AffectedHolders;
use SineMacula\Laravel\Authorization\Administration\HeldLifetime;
use SineMacula\Laravel\Authorization\Administration\RankComparison;
use SineMacula\Laravel\Authorization\Config\ConfigValidator;
use SineMacula\Laravel\Authorization\Config\SwitchConfigValidator;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;
use SineMacula\Laravel\Authorization\Reviews\Support\RoleChains;
use SineMacula\Laravel\Authorization\Support\RoleGraph;
use Tests\TestCase;

/**
 * Feature tests for the switches of the authorization config, `gate`,
 * `hierarchy` and `rank`: validated strictly at boot (N117), and read at run
 * time through one strict accessor by every reader of the role hierarchy and
 * rank switches, so none tests a value for its truthiness or fails with a
 * `TypeError`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(SwitchConfigValidator::class)]
#[CoversClass(RoleGraph::class)]
#[CoversClass(RoleChains::class)]
#[CoversClass(RankComparison::class)]
#[CoversClass(AffectedHolders::class)]
#[CoversClass(HeldLifetime::class)]
final class SwitchConfigValidatorTest extends TestCase
{
    /**
     * Each switch's block may leave `enabled` out, which is on, or set it to
     * true or false, as the environment gives `true` and `false`.
     *
     * @return void
     */
    public function testABooleanSwitchIsAccepted(): void
    {
        foreach (SwitchConfigValidator::SWITCHES as $switch) {
            SwitchConfigValidator::validate($switch, []);
            SwitchConfigValidator::validate($switch, ['enabled' => true]);
            SwitchConfigValidator::validate($switch, ['enabled' => false]);
        }

        self::assertSame(['gate', 'hierarchy', 'rank'], SwitchConfigValidator::SWITCHES);
        self::assertSame(['enabled'], SwitchConfigValidator::KEYS);
    }

    /**
     * Return each switch with a block refused for it, the path it is refused
     * under and why.
     *
     * @return iterable<string, array{string, mixed, string, string}>
     */
    public static function refusedSwitches(): iterable
    {
        foreach (SwitchConfigValidator::SWITCHES as $switch) {
            $enabled = "authorization.{$switch}.enabled";

            yield "{$switch} as null" => [$switch, null, "authorization.{$switch}", 'expected an array, got \'null\' (null).'];
            yield "{$switch} as a boolean" => [$switch, true, "authorization.{$switch}", 'expected an array, got true (bool).'];
            yield "{$switch} with an unknown key" => [$switch, ['enabeld' => true], "authorization.{$switch}.enabeld", 'unknown key \'enabeld\'; expected one of enabled.'];
            yield "{$switch} enabled as null" => [$switch, ['enabled' => null], $enabled, 'expected true or false, got \'null\' (null).'];
            yield "{$switch} enabled as off" => [$switch, ['enabled' => 'off'], $enabled, 'expected true or false, got \'off\' (string).'];
            yield "{$switch} enabled as no" => [$switch, ['enabled' => 'no'], $enabled, 'expected true or false, got \'no\' (string).'];
            yield "{$switch} enabled as a string of 0" => [$switch, ['enabled' => '0'], $enabled, 'expected true or false, got \'0\' (string).'];
            yield "{$switch} enabled as a string of true" => [$switch, ['enabled' => 'true'], $enabled, 'expected true or false, got \'true\' (string).'];
            yield "{$switch} enabled as 1" => [$switch, ['enabled' => 1], $enabled, 'expected true or false, got 1 (int).'];
            yield "{$switch} enabled as 0" => [$switch, ['enabled' => 0], $enabled, 'expected true or false, got 0 (int).'];
        }
    }

    /**
     * A switch block that is not an array, sets a key other than `enabled`, or
     * sets it to anything but true or false is refused, naming its path, at
     * boot.
     *
     * @param  string  $switch
     * @param  mixed  $block
     * @param  string  $path
     * @param  string  $reason
     * @return void
     */
    #[DataProvider('refusedSwitches')]
    public function testAMalformedSwitchIsRefusedAtBoot(string $switch, mixed $block, string $path, string $reason): void
    {
        $config          = $this->authorizationConfig();
        $config[$switch] = $block;

        $this->assertRefused(fn () => ConfigValidator::validate($config, $this->container()), $path, $reason);
    }

    /**
     * A switch block left out, or leaving `enabled` out, is on; one set is read
     * as it is set.
     *
     * @return void
     */
    public function testTheAccessorReadsTheSwitch(): void
    {
        $config = $this->container()->make(ConfigRepository::class);

        $authorization = $this->authorizationConfig();
        unset($authorization['hierarchy']);
        $config->set('authorization', $authorization);

        self::assertTrue(SwitchConfigValidator::isEnabled('hierarchy'));

        $config->set('authorization.hierarchy', []);

        self::assertTrue(SwitchConfigValidator::isEnabled('hierarchy'));

        $config->set('authorization.rank.enabled', false);

        self::assertFalse(SwitchConfigValidator::isEnabled('rank'));

        $config->set('authorization.rank.enabled', true);

        self::assertTrue(SwitchConfigValidator::isEnabled('rank'));
    }

    /**
     * A switch changed after boot to something that is not a boolean, or a
     * block that is not an array, is refused by the accessor, never read for
     * its truthiness.
     *
     * @return void
     */
    public function testTheAccessorRefusesAMalformedSwitch(): void
    {
        $config = $this->container()->make(ConfigRepository::class);

        $config->set('authorization.hierarchy.enabled', 'off');

        $this->assertRefused(static fn () => SwitchConfigValidator::isEnabled('hierarchy'), 'authorization.hierarchy.enabled', 'expected true or false, got \'off\' (string).');

        $config->set('authorization.rank', 'off');

        $this->assertRefused(static fn () => SwitchConfigValidator::isEnabled('rank'), 'authorization.rank', 'expected an array, got \'off\' (string).');

        $config->set('authorization.rank', ['enabled' => null]);

        $this->assertRefused(static fn () => SwitchConfigValidator::isEnabled('rank'), 'authorization.rank.enabled', 'expected true or false, got \'null\' (null).');
    }

    /**
     * Every reader of the role hierarchy switch refuses one that is not a
     * boolean through the accessor, rather than failing with a `TypeError` or
     * reading a string as on.
     *
     * @return void
     */
    public function testEveryHierarchyReaderRefusesAMalformedSwitch(): void
    {
        $this->container()->make(ConfigRepository::class)->set('authorization.hierarchy.enabled', 'off');

        $readers = [
            'RoleGraph'       => static fn () => RoleGraph::reach(['role']),
            'AffectedHolders' => static fn () => AffectedHolders::none()->ofRoles(['role']),
            'RoleChains'      => static fn () => (new \ReflectionMethod(RoleChains::class, 'chain'))->invoke(null, 'role', []),
            'HeldLifetime'    => static fn () => (new \ReflectionMethod(HeldLifetime::class, 'chains'))->invoke(null, []),
        ];

        foreach ($readers as $reader) {
            $this->assertRefused($reader, 'authorization.hierarchy.enabled', 'expected true or false, got \'off\' (string).');
        }
    }

    /**
     * The rank comparison refuses a rank switch that is not a boolean through
     * the accessor, and reads one that is.
     *
     * @return void
     */
    public function testTheRankReaderRefusesAMalformedSwitch(): void
    {
        $config = $this->container()->make(ConfigRepository::class);

        $config->set('authorization.rank.enabled', 1);

        $this->assertRefused(static fn () => RankComparison::isEnabled(), 'authorization.rank.enabled', 'expected true or false, got 1 (int).');

        $config->set('authorization.rank.enabled', false);

        self::assertFalse(RankComparison::isEnabled());
    }

    /**
     * Assert the callback is refused with the given config key and reason.
     *
     * @param  callable(): mixed  $callback
     * @param  string  $key
     * @param  string  $reason
     * @return void
     */
    private function assertRefused(callable $callback, string $key, string $reason): void
    {
        try {
            $callback();

            self::fail('InvalidAuthorizationConfigException was not thrown.');
        } catch (InvalidAuthorizationConfigException $exception) {
            self::assertSame($key, $exception->getConfigKey());
            self::assertSame($reason, $exception->getReason());
        }
    }
}
