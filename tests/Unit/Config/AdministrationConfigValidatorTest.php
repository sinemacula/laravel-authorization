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
     * An empty block, whose limits take their defaults, a whole `max_impact` of
     * at least 1 and a whole `retries` of at least 0 are accepted, written as
     * ints or as the environment gives whole numbers.
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
        AdministrationConfigValidator::validate(['max_impact' => '1000', 'retries' => '0']);
        AdministrationConfigValidator::validate(['max_impact' => '1', 'retries' => '2']);

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

        yield 'not an array' => ['1000', 'authorization.administration', 'expected an array, got \'1000\' (string).'];
        yield 'null' => [null, 'authorization.administration', 'expected an array, got \'null\' (null).'];
        yield 'an unknown limit' => [['max_holders' => 4], 'authorization.administration.max_holders', 'unknown key \'max_holders\'; expected one of max_impact, retries.'];
        yield 'an unknown limit after one' => [
            ['max_impact' => 5, 'max_holders' => 4],
            'authorization.administration.max_holders',
            'unknown key \'max_holders\'; expected one of max_impact, retries.',
        ];
        yield 'a list of limits' => [[5], 'authorization.administration.0', 'unknown key \'0\'; expected one of max_impact, retries.'];
        yield 'zero' => [['max_impact' => 0], 'authorization.administration.max_impact', $whole . '0 (int).'];
        yield 'zero as a string' => [['max_impact' => '0'], 'authorization.administration.max_impact', $whole . '\'0\' (string).'];
        yield 'negative' => [['max_impact' => -1], 'authorization.administration.max_impact', $whole . '-1 (int).'];
        yield 'a null max_impact' => [['max_impact' => null], 'authorization.administration.max_impact', $whole . '\'null\' (null).'];
        yield 'a string not a whole number' => [['max_impact' => '12abc'], 'authorization.administration.max_impact', $whole . '\'12abc\' (string).'];
        yield 'an exponent' => [['max_impact' => '1e3'], 'authorization.administration.max_impact', $whole . '\'1e3\' (string).'];
        yield 'a padded string' => [['max_impact' => ' 5'], 'authorization.administration.max_impact', $whole . '\' 5\' (string).'];
        yield 'an empty string' => [['max_impact' => ''], 'authorization.administration.max_impact', $whole . '\'\' (string).'];
        yield 'a float' => [['max_impact' => 1.5], 'authorization.administration.max_impact', $whole . '1.5 (float).'];
        yield 'a list' => [['max_impact' => [1]], 'authorization.administration.max_impact', $whole . '\'array\' (array).'];
        yield 'negative retries' => [['retries' => -1], 'authorization.administration.retries', $tries . '-1 (int).'];
        yield 'negative retries as a string' => [['retries' => '-1'], 'authorization.administration.retries', $tries . '\'-1\' (string).'];
        yield 'null retries' => [['retries' => null], 'authorization.administration.retries', $tries . '\'null\' (null).'];
        yield 'retries not a whole number' => [['retries' => '2.0'], 'authorization.administration.retries', $tries . '\'2.0\' (string).'];
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
