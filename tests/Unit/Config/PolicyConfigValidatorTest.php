<?php

declare(strict_types = 1);

namespace Tests\Unit\Config;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Config\PolicyConfigValidator;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;

/**
 * Unit tests for the boot-time validation of `authorization.policies`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PolicyConfigValidator::class)]
final class PolicyConfigValidatorTest extends TestCase
{
    /** @var string The path of the limits. */
    private const string LIMITS = 'authorization.policies.limits';

    /**
     * An empty block, an empty set of limits and whole limits of at least 1,
     * written as ints or as the environment gives whole numbers, are accepted;
     * a limit left out takes its default.
     *
     * @return void
     */
    public function testWholeLimitsAreAccepted(): void
    {
        PolicyConfigValidator::validate([]);
        PolicyConfigValidator::validate(['limits' => []]);
        PolicyConfigValidator::validate(['limits' => ['document_bytes' => 1, 'statements' => 100, 'conditions' => 50, 'pattern_length' => 512]]);
        PolicyConfigValidator::validate(['limits' => ['document_bytes' => '65536', 'statements' => '1']]);

        self::assertSame(['limits'], PolicyConfigValidator::SETTINGS);
        self::assertSame('authorization.policies', PolicyConfigValidator::KEY);
    }

    /**
     * Return each invalid block, with the key it is refused under and why.
     *
     * @return iterable<string, array{mixed, string, string}>
     */
    public static function invalidBlocks(): iterable
    {
        $whole = 'expected a whole number of at least 1, got ';
        $known = 'expected one of document_bytes, statements, conditions, pattern_length.';

        yield 'not an array' => ['limits', 'authorization.policies', 'expected an array, got \'limits\' (string).'];
        yield 'null' => [null, 'authorization.policies', 'expected an array, got \'null\' (null).'];
        yield 'an unknown key' => [['limit' => []], 'authorization.policies.limit', 'unknown key \'limit\'; expected one of limits.'];
        yield 'null limits' => [['limits' => null], self::LIMITS, 'expected an array, got \'null\' (null).'];
        yield 'limits not an array' => [['limits' => 100], self::LIMITS, 'expected an array, got 100 (int).'];
        yield 'an unknown limit' => [['limits' => ['statments' => 5]], self::LIMITS . '.statments', "unknown key 'statments'; {$known}"];
        yield 'zero' => [['limits' => ['statements' => 0]], self::LIMITS . '.statements', $whole . '0 (int).'];
        yield 'zero as a string' => [['limits' => ['statements' => '0']], self::LIMITS . '.statements', $whole . '\'0\' (string).'];
        yield 'negative' => [['limits' => ['conditions' => -1]], self::LIMITS . '.conditions', $whole . '-1 (int).'];
        yield 'a null limit' => [['limits' => ['conditions' => null]], self::LIMITS . '.conditions', $whole . '\'null\' (null).'];
        yield 'trailing letters' => [['limits' => ['pattern_length' => '12abc']], self::LIMITS . '.pattern_length', $whole . '\'12abc\' (string).'];
        yield 'an exponent' => [['limits' => ['document_bytes' => '1e3']], self::LIMITS . '.document_bytes', $whole . '\'1e3\' (string).'];
        yield 'a leading space' => [['limits' => ['document_bytes' => ' 5']], self::LIMITS . '.document_bytes', $whole . '\' 5\' (string).'];
        yield 'a decimal' => [['limits' => ['document_bytes' => '5.0']], self::LIMITS . '.document_bytes', $whole . '\'5.0\' (string).'];
        yield 'an empty string' => [['limits' => ['document_bytes' => '']], self::LIMITS . '.document_bytes', $whole . '\'\' (string).'];
        yield 'a float' => [['limits' => ['statements' => 1.5]], self::LIMITS . '.statements', $whole . '1.5 (float).'];
        yield 'a boolean' => [['limits' => ['statements' => true]], self::LIMITS . '.statements', $whole . 'true (bool).'];
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
            PolicyConfigValidator::validate($config);

            self::fail('The block was accepted.');
        } catch (InvalidAuthorizationConfigException $exception) {
            self::assertSame($key, $exception->getConfigKey());
            self::assertSame($reason, $exception->getReason());
        }
    }
}
