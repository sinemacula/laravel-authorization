<?php

declare(strict_types = 1);

namespace Tests\Unit\Config;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Config\RequirementCheckerConfigValidator;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;
use SineMacula\Laravel\Authorization\Resolvers\RefusingRequirementChecker;
use Tests\Feature\Stubs\StubRequirementChecker;

/**
 * Unit tests for the boot-time validation of
 * `authorization.requirement_checker`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RequirementCheckerConfigValidator::class)]
final class RequirementCheckerConfigValidatorTest extends TestCase
{
    /**
     * The default and any class implementing the contract are accepted.
     *
     * @return void
     */
    public function testAcceptsACheckerClass(): void
    {
        RequirementCheckerConfigValidator::validate(RefusingRequirementChecker::class);
        RequirementCheckerConfigValidator::validate(StubRequirementChecker::class);

        $this->addToAssertionCount(2);
    }

    /**
     * Provide values that do not name a checker, with the reason each is
     * refused.
     *
     * @return iterable<string, array{mixed, string}>
     */
    public static function refusedProvider(): iterable
    {
        yield 'null' => [null, 'a requirement checker class is required; set it to \\' . RefusingRequirementChecker::class . ' to meet no requirement.'];
        yield 'an empty string' => ['', 'expected a class-string, got string.'];
        yield 'a number' => [42, 'expected a class-string, got int.'];
        yield 'a missing class' => ['App\Missing\Checker', 'class \'App\Missing\Checker\' does not exist.'];
        yield 'another class' => [\stdClass::class, 'class \'stdClass\' does not implement SineMacula\Laravel\Authorization\Contracts\AuthenticationRequirementChecker.'];
    }

    /**
     * A value that does not name a checker is refused, under the config key,
     * with the reason.
     *
     * @param  mixed  $value
     * @param  string  $reason
     * @return void
     */
    #[DataProvider('refusedProvider')]
    public function testRefusesAValueThatNamesNoChecker(mixed $value, string $reason): void
    {
        try {
            RequirementCheckerConfigValidator::validate($value);
            self::fail('The value was accepted.');
        } catch (InvalidAuthorizationConfigException $exception) {
            self::assertSame('authorization.requirement_checker', RequirementCheckerConfigValidator::KEY);
            self::assertStringContainsString('authorization.requirement_checker', $exception->getMessage());
            self::assertStringContainsString($reason, $exception->getMessage());
        }
    }
}
