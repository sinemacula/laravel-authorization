<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Config;

use SineMacula\Laravel\Authorization\Contracts\IdentityDirectory;
use SineMacula\Laravel\Authorization\Contracts\PolicyStore;
use SineMacula\Laravel\Authorization\Contracts\ResourceTenantResolver;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Resolvers\AuthGuardSubjectResolver;
use SineMacula\Laravel\Authorization\Resolvers\FlatTenantTree;
use SineMacula\Laravel\Authorization\Resolvers\GuardUserIdentityDirectory;
use SineMacula\Laravel\Authorization\Resolvers\NoResourceTenant;
use SineMacula\Laravel\Authorization\Resolvers\RefusingRequirementChecker;

/**
 * Boot-time validator for the settings of the authorization config that name
 * the class a seam is bound to, run by `ConfigValidator`: `subject_resolver`,
 * `tenant_tree`, `identity_directory`, `resource_tenant_resolver`,
 * `requirement_checker` and `policy_store`.
 *
 * A setting left out takes the package's default. One set must name a class
 * implementing the seam's contract; null is refused, except for `policy_store`,
 * where it means no store. The provider binds the package's default in place of
 * a value that names no such class (see `SeamBindings`), so it is here, when
 * the application boots, that such a value is refused, naming the setting.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SeamConfigValidator
{
    /** @var array<string, array{class-string, class-string, string}> Each setting's contract, the package's default, and why null is refused. */
    public const array SEAMS = [
        'subject_resolver' => [
            SubjectResolver::class,
            AuthGuardSubjectResolver::class,
            'a subject resolver class is required; set it to \\' . AuthGuardSubjectResolver::class . ' to decide about the user Laravel authenticated.',
        ],
        'tenant_tree' => [
            TenantTree::class,
            FlatTenantTree::class,
            'a tenant tree class is required; set it to \\' . FlatTenantTree::class . ' for a flat set of tenants.',
        ],
        'identity_directory' => [
            IdentityDirectory::class,
            GuardUserIdentityDirectory::class,
            'an identity directory class is required; set it to \\' . GuardUserIdentityDirectory::class . ' for the default.',
        ],
        'resource_tenant_resolver' => [
            ResourceTenantResolver::class,
            NoResourceTenant::class,
            'a resource tenant resolver class is required; set it to \\' . NoResourceTenant::class . ' to read no resource\'s tenant.',
        ],
    ];

    /**
     * Validate the seam settings of the supplied authorization config, throwing
     * on the first failure.
     *
     * @param  array<array-key, mixed>  $config
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function validate(array $config): void
    {
        foreach (self::SEAMS as $key => [$contract, $default, $required]) {
            ImplementationConfigValidator::validate("authorization.{$key}", ConfigBlock::entry($config, $key, $default), $contract, $required);
        }

        RequirementCheckerConfigValidator::validate(ConfigBlock::entry($config, 'requirement_checker', RefusingRequirementChecker::class));

        $store = ConfigBlock::entry($config, 'policy_store', null);

        if ($store === null) {
            return;
        }

        ImplementationConfigValidator::validate('authorization.policy_store', $store, PolicyStore::class, '');
    }
}
