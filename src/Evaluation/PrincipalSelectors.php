<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation;

use Illuminate\Database\Eloquent\Relations\MorphToMany;
use SineMacula\Laravel\Authorization\Cache\Resolution;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Cache\ResolutionPins;
use SineMacula\Laravel\Authorization\Contracts\SupportsRoles;
use SineMacula\Laravel\Authorization\Resolvers\GrantResolver;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\SubjectGrants;

/**
 * Tells whether a resource policy's `principals` selectors name the subject of
 * one check (AUTHZ-7.3).
 *
 * A selector names the subject when it is the subject's principal or identity
 * (only one whose grants reach the principal: a person's never names a machine,
 * nor a machine's a person) by reference (`<morph type>:<id>`, the morph class
 * and key), or a role by its key (`role:<role id>`) that the principal or
 * identity holds in the scope the check is decided in: the tenant and
 * application the check runs under, read through the grantee's `roles()`
 * relation, as every other grant is. With the hierarchy enabled, a role
 * selector also names whoever holds a role below that role, as the role's
 * permissions and policies reach them; with it disabled, only whoever holds
 * that role itself. A role is named by its key, never its name, so a role of
 * the same name owned by another tenant, or held for another application, names
 * no one. A selector of the type `role` always names a role.
 *
 * The roles are read at most once for the check, and only when a selector names
 * a role and no selector names the subject by reference, through the resolution
 * cache, as the grantee's roles are (see
 * `ResolutionCache::rememberRoleKeys()`): once warm, a check reads no role. A
 * grantee whose roles do not come through a `roles()` relation holds none here.
 * Build a new instance for every check.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class PrincipalSelectors
{
    /** @var string What a role selector starts with. */
    private const string ROLE_PREFIX = StatementValidator::ROLE_SELECTOR . ':';

    /** @var array<array-key, true>|null The keys of the roles held in the check's scope, with those above them, once read. */
    private ?array $roles = null;

    /**
     * Create a new set of the subject's selectors.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     */
    public function __construct(

        /** The subject of the check. */
        private readonly Subject $subject,
    ) {}

    /**
     * Determine whether any of the selectors names the subject.
     *
     * @param  array<int, string>  $selectors
     * @return bool
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException
     */
    public function isNamedByAny(array $selectors): bool
    {
        if ($this->isNamedByReference($selectors)) {
            return true;
        }

        $roles = self::roleKeysOf($selectors);

        return $roles !== [] && \array_intersect_key($this->roles ??= $this->readRoles(), $roles) !== [];
    }

    /**
     * Return the keys of the roles the selectors name, or none when one of them
     * names the subject by reference, so the roles are not what names it.
     *
     * @param  array<int, string>  $selectors
     * @return list<string>
     */
    public function rolesNaming(array $selectors): array
    {
        return $this->isNamedByReference($selectors) ? [] : \array_keys(self::roleKeysOf($selectors));
    }

    /**
     * Determine whether any of the selectors names the subject's principal or
     * identity by reference.
     *
     * @param  array<int, string>  $selectors
     * @return bool
     */
    private function isNamedByReference(array $selectors): bool
    {
        return \array_intersect_key($this->readReferences(), \array_flip($selectors)) !== [];
    }

    /**
     * Return the subject's principal and its identity by reference, each that
     * has a morph class and a key.
     *
     * @return array<string, true>
     */
    private function readReferences(): array
    {
        $references = \array_map(static fn (object $grantee): ?string => self::referenceOf($grantee), $this->grantees());

        return \array_fill_keys(\array_filter($references, static fn (?string $reference): bool => $reference !== null), true);
    }

    /**
     * Return the keys of the roles the principal and its identity hold in the
     * check's scope, with the roles above them when the hierarchy is enabled.
     *
     * @return array<array-key, true>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException
     */
    private function readRoles(): array
    {
        $keys = [];

        foreach ($this->grantees() as $grantee) {
            foreach (self::roleKeysHeldBy($grantee) as $key) {
                $keys[$key] = true;
            }
        }

        return $keys;
    }

    /**
     * Return the role keys the role selectors among the selectors name.
     *
     * @param  array<int, string>  $selectors
     * @return array<string, true>
     */
    private static function roleKeysOf(array $selectors): array
    {
        $roles = [];

        foreach ($selectors as $selector) {
            if (!\str_starts_with($selector, self::ROLE_PREFIX)) {
                continue;
            }

            $roles[\substr($selector, \strlen(self::ROLE_PREFIX))] = true;
        }

        return $roles;
    }

    /**
     * Return the keys of the roles the grantee holds in the check's scope, with
     * the roles above them when the hierarchy is enabled, read through its
     * `roles()` relation and the resolution cache, or none for a grantee
     * without one.
     *
     * @param  object  $grantee
     * @return list<string>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException
     */
    private static function roleKeysHeldBy(object $grantee): array
    {
        $relation = $grantee instanceof SupportsRoles && \method_exists($grantee, 'roles') ? $grantee->roles() : null;

        if (!$relation instanceof MorphToMany) {
            return [];
        }

        /** @var \Illuminate\Database\Eloquent\Relations\MorphToMany<\SineMacula\Laravel\Authorization\Models\Role, \Illuminate\Database\Eloquent\Model> $relation */
        $resolve = static fn (ResolutionPins $pins): Resolution => GrantResolver::roleKeys($relation, $pins);

        return ResolutionCache::instance()?->rememberRoleKeys($grantee, $resolve) ?? $resolve(new ResolutionPins)->value;
    }

    /**
     * Return the subject's principal, and its identity when that is another
     * object whose grants reach the principal: both machines or neither (see
     * `SubjectGrants::grantingIdentity()`).
     *
     * @return list<object>
     */
    private function grantees(): array
    {
        $identity = SubjectGrants::grantingIdentity($this->subject);

        return $identity === null ? [$this->subject->subject] : [$this->subject->subject, $identity];
    }

    /**
     * Return the grantee as `<morph type>:<id>`, or null when it has no morph
     * class or no key.
     *
     * @param  object  $grantee
     * @return string|null
     */
    private static function referenceOf(object $grantee): ?string
    {
        if (!\method_exists($grantee, 'getMorphClass') || !\method_exists($grantee, 'getKey')) {
            return null;
        }

        $type = $grantee->getMorphClass();
        $key  = $grantee->getKey();

        return \is_string($type) && $type !== '' && (\is_string($key) || \is_int($key)) && (string) $key !== '' ? "{$type}:{$key}" : null;
    }
}
