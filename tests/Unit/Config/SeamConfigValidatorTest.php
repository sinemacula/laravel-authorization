<?php

declare(strict_types = 1);

namespace Tests\Unit\Config;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Config\SeamConfigValidator;
use SineMacula\Laravel\Authorization\Contracts\AuthenticationRequirementChecker;
use SineMacula\Laravel\Authorization\Contracts\PolicyStore;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;
use SineMacula\Laravel\Authorization\Resolvers\RefusingRequirementChecker;
use Tests\Feature\Stubs\StubPolicyStore;

/**
 * Unit tests for the boot-time validation of the settings that name the class a
 * seam is bound to.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SeamConfigValidator::class)]
final class SeamConfigValidatorTest extends TestCase
{
    /**
     * A config setting none of the seams takes every default, one naming each
     * default passes, and a null policy store means none.
     *
     * @return void
     */
    public function testMissingSettingsTakeTheirDefaults(): void
    {
        SeamConfigValidator::validate([]);

        $defaults = \array_map(static fn (array $seam): string => $seam[1], SeamConfigValidator::SEAMS);

        SeamConfigValidator::validate([...$defaults, 'requirement_checker' => RefusingRequirementChecker::class, 'policy_store' => null]);
        SeamConfigValidator::validate(['policy_store' => StubPolicyStore::class]);

        self::assertSame(['subject_resolver', 'tenant_tree', 'identity_directory', 'resource_tenant_resolver'], \array_keys(SeamConfigValidator::SEAMS));
    }

    /**
     * Return each seam setting, with a value refused for it and why.
     *
     * @return iterable<string, array{string, mixed, string}>
     */
    public static function refusedSettings(): iterable
    {
        foreach (SeamConfigValidator::SEAMS as $key => [$contract, , $required]) {
            yield "{$key} as null" => [$key, null, $required];
            yield "{$key} as an int" => [$key, 42, 'expected a class-string, got int.'];
            yield "{$key} as an empty string" => [$key, '', 'expected a class-string, got string.'];
            yield "{$key} as an array" => [$key, [$contract], 'expected a class-string, got array.'];
            yield "{$key} naming no class" => [$key, 'App\Missing', 'class \'App\Missing\' does not exist.'];
            yield "{$key} naming another class" => [$key, \stdClass::class, "class 'stdClass' does not implement {$contract}."];
        }

        yield 'requirement_checker as null' => [
            'requirement_checker',
            null,
            'a requirement checker class is required; set it to \\' . RefusingRequirementChecker::class . ' to meet no requirement.',
        ];
        yield 'requirement_checker naming another class' => [
            'requirement_checker',
            \stdClass::class,
            'class \'stdClass\' does not implement ' . AuthenticationRequirementChecker::class . '.',
        ];
        yield 'policy_store as an int' => ['policy_store', 42, 'expected a class-string, got int.'];
        yield 'policy_store as an empty string' => ['policy_store', '', 'expected a class-string, got string.'];
        yield 'policy_store naming another class' => ['policy_store', \stdClass::class, 'class \'stdClass\' does not implement ' . PolicyStore::class . '.'];
    }

    /**
     * A setting that names no class implementing the seam's contract is
     * refused, naming the setting; null is refused, except for the policy
     * store.
     *
     * @param  string  $key
     * @param  mixed  $value
     * @param  string  $reason
     * @return void
     */
    #[DataProvider('refusedSettings')]
    public function testAMalformedSettingIsRefused(string $key, mixed $value, string $reason): void
    {
        try {
            SeamConfigValidator::validate([$key => $value]);

            self::fail('The setting was accepted.');
        } catch (InvalidAuthorizationConfigException $exception) {
            self::assertSame("authorization.{$key}", $exception->getConfigKey());
            self::assertSame($reason, $exception->getReason());
        }
    }
}
