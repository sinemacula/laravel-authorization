<?php

declare(strict_types = 1);

namespace Tests\Unit\Context;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Context\AssuranceKeys;

/**
 * Unit tests for the assurance keys no condition may test.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AssuranceKeys::class)]
final class AssuranceKeysTest extends TestCase
{
    /**
     * Provide paths with whether each is an assurance key when the
     * authentication context contributes `mfa`.
     *
     * @return iterable<string, array{string, bool}>
     */
    public static function pathProvider(): iterable
    {
        foreach (AssuranceKeys::NAMES as $name) {
            yield "authentication.{$name}" => ["authentication.{$name}", true];
            yield "mfa.{$name}" => ["mfa.{$name}", true];
            yield "input.{$name}" => ["input.{$name}", false];
        }

        yield 'a nested assurance segment' => ['mfa.factors.amr', true];
        yield 'under an assurance segment' => ['authentication.amr.0', true];
        yield 'an ordinary authentication key' => ['authentication.guard', false];
        yield 'the namespace alone' => ['authentication', false];
        yield 'a namespace not contributed' => ['sso.amr', false];
        yield 'a name as the namespace' => ['amr.value', false];
        yield 'a name with a suffix' => ['authentication.amr_count', false];
        yield 'an empty path' => ['', false];
    }

    /**
     * A key is an assurance key when it belongs to `authentication` or to a
     * contributed namespace and a segment after the namespace is a fixed name.
     *
     * @param  string  $path
     * @param  bool  $isAssuranceKey
     * @return void
     */
    #[DataProvider('pathProvider')]
    public function testRecognisesAssuranceKeys(string $path, bool $isAssuranceKey): void
    {
        self::assertSame($isAssuranceKey, AssuranceKeys::isAssuranceKey($path, ['mfa']));
    }

    /**
     * Without contributed namespaces only `authentication` holds assurance
     * keys.
     *
     * @return void
     */
    public function testOnlyAuthenticationWithoutContributedNamespaces(): void
    {
        self::assertTrue(AssuranceKeys::isAssuranceKey('authentication.auth_time'));
        self::assertFalse(AssuranceKeys::isAssuranceKey('mfa.auth_time'));
    }

    /**
     * The names are the fixed list, and the reason points at the requirement
     * operator.
     *
     * @return void
     */
    public function testTheNamesAndReasonAreFixed(): void
    {
        self::assertSame(['assurance_level', 'auth_time', 'seconds_since_step_up', 'last_verified_at', 'verification_age', 'multifactor', 'amr'], AssuranceKeys::NAMES);
        self::assertSame('authentication', AssuranceKeys::NAMESPACE);
        self::assertSame(
            'is an assurance key, which no condition may test or reference; '
            . 'state the requirement with the authentication_requirement operator on the key \'authentication\' instead.',
            AssuranceKeys::REASON,
        );
    }
}
