<?php

declare(strict_types = 1);

namespace Tests\Unit\Context;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Context\AssuranceKeys;
use Tests\Feature\Stubs\ContributingAuthenticationContext;

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
     * Provide paths with whether each is an assurance key when the
     * authentication context contributes `mfa` and `sso` and declares
     * `recovery_code` and `provider_*`.
     *
     * @return iterable<string, array{string, bool}>
     */
    public static function declaredProvider(): iterable
    {
        yield 'an exact declared name' => ['mfa.recovery_code', true];
        yield 'an exact declared name under authentication' => ['authentication.recovery_code', true];
        yield 'an exact declared name nested' => ['mfa.factors.recovery_code.count', true];
        yield 'a declared name with a suffix' => ['mfa.recovery_codes', false];
        yield 'a declared name with a prefix' => ['mfa.old_recovery_code', false];
        yield 'a prefix match' => ['sso.provider_name', true];
        yield 'the prefix alone' => ['sso.provider_', true];
        yield 'a prefix match nested' => ['sso.session.provider_id', true];
        yield 'the prefix without its underscore' => ['sso.provider', false];
        yield 'a prefix inside a segment' => ['sso.the_provider_name', false];
        yield 'a declared name outside the namespaces' => ['input.recovery_code', false];
        yield 'a prefix match outside the namespaces' => ['input.provider_name', false];
        yield 'a fixed name still' => ['sso.amr', true];
        yield 'an ordinary key' => ['sso.tenant', false];
    }

    /**
     * A key is an assurance key when a segment after a contributed namespace is
     * a name the context declares, or starts with a declared prefix.
     *
     * @param  string  $path
     * @param  bool  $isAssuranceKey
     * @return void
     */
    #[DataProvider('declaredProvider')]
    public function testRecognisesDeclaredNamesAndPrefixes(string $path, bool $isAssuranceKey): void
    {
        $keys = new AssuranceKeys(['mfa', 'sso'], ['recovery_code', 'provider_*']);

        self::assertSame($isAssuranceKey, $keys->matches($path));
        self::assertSame($isAssuranceKey, AssuranceKeys::isAssuranceKey($path, ['mfa', 'sso'], ['recovery_code', 'provider_*']));
    }

    /**
     * The declared names follow the fixed ones, which a context never removes.
     *
     * @return void
     */
    public function testTheDeclaredNamesFollowTheFixedOnes(): void
    {
        $keys = new AssuranceKeys(['mfa'], ['level', 'factor_*']);

        self::assertSame(['mfa'], $keys->namespaces);
        self::assertSame([...AssuranceKeys::NAMES, 'level', 'factor_*'], $keys->names);
        self::assertSame(AssuranceKeys::NAMES, (new AssuranceKeys)->names);
        self::assertSame([], (new AssuranceKeys)->namespaces);
    }

    /**
     * The keys of a context are its namespaces and the names it declares, and
     * without a context only `authentication` holds the fixed names.
     *
     * @return void
     */
    public function testReadsTheContextsNamespacesAndNames(): void
    {
        $keys = AssuranceKeys::of(new ContributingAuthenticationContext(['mfa'], ['level']));

        self::assertSame(['authentication', 'mfa'], $keys->namespaces);
        self::assertSame([...AssuranceKeys::NAMES, 'level'], $keys->names);
        self::assertTrue($keys->matches('mfa.level'));
        self::assertFalse(AssuranceKeys::of(null)->matches('mfa.amr'));
        self::assertTrue(AssuranceKeys::of(null)->matches('authentication.amr'));
        self::assertFalse(AssuranceKeys::of(null)->matches('authentication.level'));
    }

    /**
     * Provide declarations that are refused, with what the refusal names.
     *
     * @return iterable<string, array{array<array-key, mixed>, string}>
     */
    public static function malformedProvider(): iterable
    {
        yield 'not a string' => [['level', 3], 'int'];
        yield 'null' => [[null], 'null'];
        yield 'an empty name' => [[''], '\'\''];
        yield 'a star alone' => [['*'], '\'*\''];
        yield 'a dot' => [['mfa.level'], '\'mfa.level\''];
        yield 'a trailing dot' => [['level.'], '\'level.\''];
        yield 'a dot before the star' => [['provider.*'], '\'provider.*\''];
        yield 'a leading star' => [['*_name'], '\'*_name\''];
        yield 'a star inside' => [['provider_*_name'], '\'provider_*_name\''];
        yield 'two trailing stars' => [['provider_**'], '\'provider_**\''];
    }

    /**
     * A malformed declaration is refused, naming the context and the entry, so
     * it fails closed rather than leaving a key testable.
     *
     * @param  array<array-key, mixed>  $declared
     * @param  string  $given
     * @return void
     */
    #[DataProvider('malformedProvider')]
    public function testRefusesAMalformedDeclaration(array $declared, string $given): void
    {
        $context = new ContributingAuthenticationContext(['mfa'], $declared);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(
            'Authentication context \'' . ContributingAuthenticationContext::class . "' declares the assurance key {$given}, "
            . 'which must be a name with no \'.\', or a name followed by one trailing \'*\'.',
        );

        AssuranceKeys::of($context);
    }

    /**
     * A declaration that is not a list is refused, and a declaration made
     * without a context names the authentication context.
     *
     * @return void
     */
    public function testRefusesADeclarationThatIsNotAList(): void
    {
        try {
            AssuranceKeys::of(new ContributingAuthenticationContext(['mfa'], ['level' => 'level']));
            self::fail('A declaration that is not a list was accepted.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame(
                'Authentication context \'' . ContributingAuthenticationContext::class . '\' must declare its assurance keys as a list, '
                . 'each a name with no \'.\', or a name followed by one trailing \'*\'.',
                $exception->getMessage(),
            );
        }

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('The authentication context declares the assurance key \'a.b\'');

        new AssuranceKeys([], ['a.b']);
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
        self::assertSame('/\A[^.*]+\*?\z/', AssuranceKeys::NAME_PATTERN);
        self::assertSame(
            'is an assurance key, which no condition may test or reference; '
            . 'state the requirement with the authentication_requirement operator on the key \'authentication\' instead.',
            AssuranceKeys::REASON,
        );
    }
}
