<?php

declare(strict_types = 1);

namespace Tests\Unit\Config;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Config\AdministrationConfigValidator;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;

/**
 * Unit tests for the boot-time validation of `authorization.administration`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AdministrationConfigValidator::class)]
final class AdministrationConfigValidatorTest extends TestCase
{
    /**
     * No block, an empty one, a whole `max_impact` of at least 1 and a whole
     * `retries` of at least 0 are accepted.
     *
     * @return void
     */
    public function testAWholeLimitIsAccepted(): void
    {
        AdministrationConfigValidator::validate([]);
        AdministrationConfigValidator::validate(['max_impact' => 1]);
        AdministrationConfigValidator::validate(['max_impact' => 1000]);
        AdministrationConfigValidator::validate(['retries' => 0]);
        AdministrationConfigValidator::validate(['max_impact' => 5, 'retries' => 7]);

        self::assertSame(['max_impact', 'retries'], AdministrationConfigValidator::LIMITS);
        self::assertSame('authorization.administration', AdministrationConfigValidator::KEY);
    }

    /**
     * Return each invalid block, with the key it is refused under and why.
     *
     * @return iterable<string, array{mixed, string, string}>
     */
    public static function invalidBlocks(): iterable
    {
        $whole = 'expected a whole number of at least 1, got ';
        $tries = 'expected a whole number of at least 0, got ';

        yield 'not an array' => ['1000', 'authorization.administration', 'expected an array of limits, got \'1000\' (string).'];
        yield 'an unknown limit' => [['max_holders' => 4], 'authorization.administration', 'unknown limit \'max_holders\'; expected one of max_impact, retries.'];
        yield 'an unknown limit after one' => [
            ['max_impact' => 5, 'max_holders' => 4],
            'authorization.administration',
            'unknown limit \'max_holders\'; expected one of max_impact, retries.',
        ];
        yield 'a list of limits' => [[5], 'authorization.administration', 'unknown limit \'0\'; expected one of max_impact, retries.'];
        yield 'zero' => [['max_impact' => 0], 'authorization.administration.max_impact', $whole . '0 (int).'];
        yield 'negative' => [['max_impact' => -1], 'authorization.administration.max_impact', $whole . '-1 (int).'];
        yield 'a string' => [['max_impact' => '1000'], 'authorization.administration.max_impact', $whole . '\'1000\' (string).'];
        yield 'a float' => [['max_impact' => 1.5], 'authorization.administration.max_impact', $whole . '1.5 (float).'];
        yield 'a list' => [['max_impact' => [1]], 'authorization.administration.max_impact', $whole . '\'array\' (array).'];
        yield 'negative retries' => [['retries' => -1], 'authorization.administration.retries', $tries . '-1 (int).'];
        yield 'retries as a string' => [['retries' => '2'], 'authorization.administration.retries', $tries . '\'2\' (string).'];
        yield 'fractional retries' => [['retries' => 0.5], 'authorization.administration.retries', $tries . '0.5 (float).'];
        yield 'retries checked after a valid limit' => [['max_impact' => 3, 'retries' => true], 'authorization.administration.retries', $tries . 'true (bool).'];
    }

    /**
     * Anything else is refused under its key, saying exactly why.
     *
     * @param  mixed  $config
     * @param  string  $key
     * @param  string  $reason
     * @return void
     */
    #[DataProvider('invalidBlocks')]
    public function testAnInvalidBlockIsRefused(mixed $config, string $key, string $reason): void
    {
        try {
            AdministrationConfigValidator::validate($config);

            self::fail('The block was accepted.');
        } catch (InvalidAuthorizationConfigException $exception) {
            self::assertSame("Invalid authorization config at '{$key}': {$reason}", $exception->getMessage());
            self::assertSame($key, $exception->getConfigKey());
        }
    }
}
