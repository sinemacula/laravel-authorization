<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Services;

use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\QueryException;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableTenant;
use SineMacula\Laravel\Authorization\Contracts\IdentityDirectory;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
use SineMacula\Laravel\Authorization\Enums\GrantPresence;
use SineMacula\Laravel\Authorization\Enums\GrantScopeStatus;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\AuthorizationLog;
use SineMacula\Laravel\Authorization\Support\GrantRoots;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\SubjectGrants;
use SineMacula\Laravel\Authorization\Support\TenantChain;

/**
 * Answers where an identity's grants lie against a tenant (AUTHZ-14.2), and
 * whether a principal holds a grant that applies in one (AUTHZ-13.8): two
 * factual questions about grants, for a trusted integration such as
 * `laravel-iam` composing SSO's principal scope or tenant admission.
 *
 * Neither authorises anything: `check()` stays the one decision path (D22).
 * Neither says whether a principal is a member of a tenant, which is the
 * application's (AUTHZ-13.9), nor whether it may act there. A grant is a live
 * role, direct permission or policy attachment, a policy that only denies
 * included; an expired row, a boundary and a guardrail are not (N82, see
 * `GrantRoots`).
 *
 * This is a trusted service, not an endpoint for users: even its bare answer
 * tells a caller something about grants in other tenants, so it is never
 * exposed to a user who may not see them. It returns the answer alone, never
 * the tenants, grants, names, counts or rows behind it.
 *
 * Each answer reads the grants in one query on the write connection, however
 * many grants and principals there are and however deep the tree, plus the
 * tree's own reads and the identity directory's; only when the tree's subtree
 * query fails as it runs is a second read, for the platform-wide grants, made.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class GrantScopeQuery
{
    /**
     * Create a new grant scope query.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** Container the identity directory, the subject resolver and the tenant tree are read from on every call. */
        private Container $container,
    ) {}

    /**
     * Return where the grants of the identity and of every principal it owns
     * lie against the tenant, in every application and under every guard.
     *
     * A grant rooted at the tenant, or below it in the bound tree, is within;
     * one rooted at an ancestor (a grant reaching the ancestor's subtree
     * included), a sibling, any other tenant or the platform is outside. The
     * answer is `OUTSIDE` as soon as one grant is proven outside, whether or
     * not the principals are all known. It is `WITHIN` only when the identity
     * directory lists the principals completely and every grant is within, or
     * there is none (N82). Otherwise it is `UNKNOWN`: an incomplete list of
     * principals, a tree that cannot be read (its subtree query failing as it
     * runs included, written to the log), or a grant row naming half a tenant.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $identity
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Contracts\AuthorizableTenant|\SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @return \SineMacula\Laravel\Authorization\Enums\GrantScopeStatus
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidTenantException
     * @throws \Throwable
     */
    public function forIdentity(Reference $identity, AuthorizableTenant|Model|Reference $tenant): GrantScopeStatus
    {
        $scope      = self::referenceTo($tenant);
        $principals = $this->directory()->principalsOf($identity);
        $status     = self::placed(new GrantRoots([$identity, ...$principals->principals]), $scope);

        return $status === GrantScopeStatus::OUTSIDE || $principals->isComplete ? $status : GrantScopeStatus::UNKNOWN;
    }

    /**
     * Return whether the principal holds a live grant that applies in the
     * tenant, as a check there reads it: its own grants, and its identity's
     * when they reach it (see `SubjectGrants::grantingIdentity()`); a grant
     * made in the tenant, one made in an ancestor that reaches below it, and a
     * platform-wide one. A grant of another principal of the same identity
     * never counts.
     *
     * Given an application, only the grants that hold in it count; without one,
     * a grant counts whichever application it holds in. A subject is taken as
     * it is; any other object becomes one as the bound subject resolver's
     * `forUser()` makes it.
     *
     * The answer is `PRESENT` only when such a grant is found, and `UNKNOWN`
     * when none is found but one could not be ruled out: the tree cannot be
     * read (only the grants made in the tenant itself and the platform-wide
     * ones are then looked for), or a grantee is not a model or reference whose
     * grants can be read. It is never membership, nor permission to act in the
     * tenant.
     *
     * @param  object|\SineMacula\Laravel\Authorization\Subject  $principal
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Contracts\AuthorizableTenant|\SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @param  string|null  $application
     * @return \SineMacula\Laravel\Authorization\Enums\GrantPresence
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidTenantException
     */
    public function hasGrantIn(object $principal, AuthorizableTenant|Model|Reference $tenant, ?string $application = null): GrantPresence
    {
        $scope   = self::referenceTo($tenant);
        $subject = $principal instanceof Subject ? $principal : $this->resolver()->forUser($principal);
        $chain   = self::chainOf($scope);

        [$grantees, $isEveryGranteeRead] = self::granteesOf($subject);

        $isPresent = (new GrantRoots($grantees))->appliesIn($chain ?? new TenantChain([$scope]), $application);

        return match (true) {
            $isPresent                              => GrantPresence::PRESENT,
            $chain === null || !$isEveryGranteeRead => GrantPresence::UNKNOWN,
            default                                 => GrantPresence::ABSENT,
        };
    }

    /**
     * Return the references to the subject and to its identity when that grants
     * to it, and whether each of them could be named by one.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @return array{0: list<\SineMacula\Laravel\Authorization\Support\Reference>, 1: bool}
     */
    private static function granteesOf(Subject $subject): array
    {
        $grantees     = [];
        $isEveryNamed = true;

        foreach (\array_filter([$subject->subject, SubjectGrants::grantingIdentity($subject)]) as $grantee) {
            if ($grantee instanceof Model || $grantee instanceof Reference) {
                $grantees[] = Reference::of($grantee);

                continue;
            }

            $isEveryNamed = false;
        }

        return [$grantees, $isEveryNamed];
    }

    /**
     * Return where the roots lie against the tenant in the bound tree. When the
     * tree cannot be read, its subtree query failing as the grant query runs
     * included, only a root at the platform is proven outside, and the answer
     * is otherwise `UNKNOWN`, never `WITHIN`. A grant table that cannot be read
     * fails that second read too, and is thrown.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\GrantRoots  $roots
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @return \SineMacula\Laravel\Authorization\Enums\GrantScopeStatus
     *
     * @throws \Throwable
     */
    private static function placed(GrantRoots $roots, Reference $tenant): GrantScopeStatus
    {
        $status = self::nested($roots, self::withinOf($tenant));

        return $status ?? ($roots->against(null) === GrantScopeStatus::OUTSIDE ? GrantScopeStatus::OUTSIDE : GrantScopeStatus::UNKNOWN);
    }

    /**
     * Return where the roots lie against the condition, or null without one or
     * when the tree's subtree query, nested in the grant query, fails as it
     * runs: a closure table missing, say, or a column of another type.
     *
     * The grant query runs in a transaction of its own, a savepoint inside the
     * caller's, so a failure rolls back only that query and leaves the caller's
     * transaction usable, as PostgreSQL otherwise would not. Only a failure of
     * the query is caught, and written to the log as a tree that cannot be
     * read; whatever else goes wrong is thrown.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\GrantRoots  $roots
     * @param  (\Closure(\Illuminate\Database\Query\Builder, string): void)|null  $within
     * @return \SineMacula\Laravel\Authorization\Enums\GrantScopeStatus|null
     *
     * @throws \Throwable
     */
    private static function nested(GrantRoots $roots, ?\Closure $within): ?GrantScopeStatus
    {
        if ($within === null) {
            return null;
        }

        try {
            return AuthorizationConnection::connection()->transaction(static fn (): GrantScopeStatus => $roots->against($within));
        } catch (QueryException $exception) {
            self::unreadable($exception);

            return null;
        }
    }

    /**
     * Return the condition a grant row meets when it is rooted at the tenant or
     * below it in the bound tree, or null when the tree cannot be read.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @return (\Closure(\Illuminate\Database\Query\Builder, string): void)|null
     */
    private static function withinOf(Reference $tenant): ?\Closure
    {
        return self::fromTree(static fn (): \Closure => GrantRoots::within($tenant, TenantChain::tree()));
    }

    /**
     * Return the tenant's chain in the bound tree, or null when the tree cannot
     * be read.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @return \SineMacula\Laravel\Authorization\Support\TenantChain|null
     */
    private static function chainOf(Reference $tenant): ?TenantChain
    {
        return self::fromTree(static fn (): TenantChain => TenantChain::of($tenant, TenantChain::tree()));
    }

    /**
     * Return what the read of the bound tree returns, or null when the tree
     * cannot be read: the application's tree may fail in any way, and a failure
     * is an answer the query cannot give, never one it guesses.
     *
     * @template TRead
     *
     * @param  \Closure(): TRead  $read
     * @return TRead|null
     */
    private static function fromTree(\Closure $read): mixed
    {
        try {
            return $read();
        } catch (\Throwable $exception) {
            self::unreadable($exception);

            return null;
        }
    }

    /**
     * Write a tree that cannot be read to the log channel, with the failure's
     * class and message, so the `UNKNOWN` it leads to can be traced.
     *
     * @param  \Throwable  $exception
     * @return void
     */
    private static function unreadable(\Throwable $exception): void
    {
        AuthorizationLog::warning('Authorization: the tenant tree could not be read for a grant scope query: ' . $exception->getMessage(), [
            'exception' => $exception::class,
        ]);
    }

    /**
     * Return the reference to the tenant.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Contracts\AuthorizableTenant|\SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @return \SineMacula\Laravel\Authorization\Support\Reference
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidTenantException
     */
    private static function referenceTo(AuthorizableTenant|Model|Reference $tenant): Reference
    {
        return $tenant instanceof Reference ? $tenant : new Reference(...TenantScope::extractTenantPair($tenant));
    }

    /**
     * Return the bound identity directory.
     *
     * @return \SineMacula\Laravel\Authorization\Contracts\IdentityDirectory
     */
    private function directory(): IdentityDirectory
    {
        /** @var \SineMacula\Laravel\Authorization\Contracts\IdentityDirectory */
        return $this->container->make(IdentityDirectory::class);
    }

    /**
     * Return the bound subject resolver.
     *
     * @return \SineMacula\Laravel\Authorization\Contracts\SubjectResolver
     */
    private function resolver(): SubjectResolver
    {
        /** @var \SineMacula\Laravel\Authorization\Contracts\SubjectResolver */
        return $this->container->make(SubjectResolver::class);
    }
}
