<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Config;

use SineMacula\Laravel\Authorization\Contracts\AuthenticationRequirementChecker;
use SineMacula\Laravel\Authorization\Resolvers\RefusingRequirementChecker;

/**
 * Boot-time validator for the `authorization.requirement_checker` config (N34),
 * run by `ConfigValidator`.
 *
 * The value must name a class implementing `AuthenticationRequirementChecker`.
 * Null is refused rather than read as "no checker", so a missing checker fails
 * at boot instead of changing how requirements are judged.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RequirementCheckerConfigValidator
{
    /** @var string The config key validated. */
    public const string KEY = 'authorization.requirement_checker';

    /**
     * Validate the supplied `requirement_checker` value, throwing when it does
     * not name a class implementing the contract.
     *
     * @param  mixed  $value
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function validate(mixed $value): void
    {
        $required = 'a requirement checker class is required; set it to \\' . RefusingRequirementChecker::class . ' to meet no requirement.';

        ImplementationConfigValidator::validate(self::KEY, $value, AuthenticationRequirementChecker::class, $required);
    }
}
