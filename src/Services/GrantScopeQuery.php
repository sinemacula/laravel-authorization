<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Services;

use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Connection;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Query\Builder;
use Illuminate\Database\QueryException;
use SineMacula\Laravel\Authorization\Config\ModelClasses;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableTenant;
use SineMacula\Laravel\Authorization\Contracts\IdentityDirectory;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
use SineMacula\Laravel\Authorization\Database\GrantApplications;
use SineMacula\Laravel\Authorization\Database\LiveGrants;
use SineMacula\Laravel\Authorization\Diagnostics\PackageState;
use SineMacula\Laravel\Authorization\Enums\GrantPresence;
use SineMacula\Laravel\Authorization\Enums\GrantScopeStatus;
use SineMacula\Laravel\Authorization\Enums\GrantTarget;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\AuthorizationLog;
use SineMacula\Laravel\Authorization\Support\GrantRoots;
use SineMacula\Laravel\Authorization\Support\InlinePolicies;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\SubjectGrants;
use SineMacula\Laravel\Authorization\Support\TenantChain;

/**
 * Answers where an identity's grants lie against a tenant (AUTHZ-14.2), whether
 * a principal holds a grant that applies in one (AUTHZ-13.8), and whose grants
 * reach a tenant or lie within its subtree (N131): factual questions about
 * grants, for a trusted integration such as `laravel-iam` composing SSO's
 * principal scope or tenant admission, or reporting the grantees a move of a
 * tenant widens.
 *
 * None authorises anything: `check()` stays the one decision path (D22). None
 * says whether a principal is a member of a tenant, which is the application's
 * (AUTHZ-13.9), nor whether it may act there. A grant is a live role, direct
 * permission or policy attachment, a policy that only denies included; an
 * expired row, a boundary and a guardrail are not (N82, see `GrantRoots`).
 *
 * This is a trusted service, not an endpoint for users: even its bare answer
 * tells a caller something about grants in other tenants, so it is never
 * exposed to a user who may not see them. The two questions about one grantee
 * return the answer alone, never the tenants, grants, names, counts or rows
 * behind it; the two about a tenant return the grantees alone, never their
 * grants.
 *
 * Each answer reads the grants in one query on the write connection, however
 * many grants and grantees there are and however deep the tree, plus the tree's
 * own reads and the identity directory's; only when the tree's subtree query
 * fails as it runs is a second read, for the platform-wide grants, made for
 * `forIdentity()`.
 *
 * Each answer refuses, before the tenant is read or a seam resolved, while the
 * package is not healthy (see `PackageState`).
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
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     * @throws \Throwable
     */
    public function forIdentity(Reference $identity, AuthorizableTenant|Model|Reference $tenant): GrantScopeStatus
    {
        PackageState::guard($this->container);

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
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public function hasGrantIn(object $principal, AuthorizableTenant|Model|Reference $tenant, ?string $application = null): GrantPresence
    {
        PackageState::guard($this->container);

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
     * Return every grantee, a principal or an identity as its rows store it,
     * holding a live grant that reaches the tenant: one made in the tenant, one
     * made in an ancestor that reaches below it, or a platform-wide one, as a
     * check there reads them (N131). A grant made in an ancestor for that
     * ancestor alone, and a row naming half a tenant, never reach it.
     *
     * A subtree moved under a new parent comes to be reached by the grants that
     * reach the parent from above it or were made there reaching below it, so a
     * caller asks this of the moved tenant once it has moved, or of the new
     * parent at any time, which lists as well whoever holds a grant made there
     * for the parent alone; the subtree's own grants keep their reach. The
     * ancestors are read from the bound tree afresh, never a batch's kept
     * answer, so a move the tree has not been told of is seen.
     *
     * Given an application, only the grants that hold in it count; without one,
     * a grant counts whichever application it holds in. The grantees are each
     * listed once, by type and then key, byte by byte. A tree that throws is
     * thrown, never answered as an empty list.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Contracts\AuthorizableTenant|\SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @param  string|null  $application
     * @return list<\SineMacula\Laravel\Authorization\Support\Reference>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidTenantException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public function granteesReaching(AuthorizableTenant|Model|Reference $tenant, ?string $application = null): array
    {
        PackageState::guard($this->container);

        $chain = TenantChain::of(self::referenceTo($tenant), TenantChain::tree(), isFresh: true);

        return self::holding(static function (Builder $query, string $table) use ($chain): void {
            $chain->grants($query, $table);

            $query->where(static function (Builder $whole) use ($table): void {
                $whole->whereNotNull($table . '.tenant_type')->orWhereNull($table . '.tenant_id');
            });
        }, $application);
    }

    /**
     * Return every grantee, a principal or an identity as its rows store it,
     * holding a live grant made in the tenant or in any tenant below it in the
     * bound tree, whether or not it reaches below its own tenant (N131). A
     * grant made in an ancestor, one platform-wide, and a row naming half a
     * tenant, are not within.
     *
     * The subtree is nested whole in the grant query, as `forIdentity()` nests
     * it, never loaded, so it must be a query on the package's connection; any
     * other is refused with an `UnexpectedValueException`, and a tree that
     * throws is thrown, never answered as an empty list. The grant query runs
     * in a savepoint of its own, so a subtree query that fails as it runs rolls
     * back only that query before its `QueryException` is thrown.
     *
     * Given an application, only the grants that hold in it count; without one,
     * a grant counts whichever application it holds in. The grantees are each
     * listed once, by type and then key, byte by byte.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Contracts\AuthorizableTenant|\SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @param  string|null  $application
     * @return list<\SineMacula\Laravel\Authorization\Support\Reference>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidTenantException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     * @throws \UnexpectedValueException
     * @throws \Throwable
     */
    public function granteesWithin(AuthorizableTenant|Model|Reference $tenant, ?string $application = null): array
    {
        PackageState::guard($this->container);

        $within = GrantRoots::within(self::referenceTo($tenant), TenantChain::tree());

        return AuthorizationConnection::connection()->transaction(static fn (): array => self::holding($within, $application));
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
     * Return every grantee holding a live grant that meets the condition and
     * holds in the application, read from every grant table in one query on the
     * write connection, each grantee once, by type and then key, byte by byte,
     * as every database orders them alike. An inline policy attached to a
     * grantee it does not belong to is no grant (see `InlinePolicies`), and a
     * role a policy is attached to no grantee: whoever holds the role is listed
     * through their own grant of it (see `RolePolicies`).
     *
     * @param  \Closure(\Illuminate\Database\Query\Builder, string): void  $constrain
     * @param  string|null  $application
     * @return list<\SineMacula\Laravel\Authorization\Support\Reference>
     */
    private static function holding(\Closure $constrain, ?string $application): array
    {
        $connection = AuthorizationConnection::connection();
        $union      = null;

        foreach (GrantTarget::cases() as $target) {
            $rows  = self::holdersIn($connection, $target, $constrain, $application);
            $union = $union === null ? $rows : $union->union($rows);
        }

        return Reference::sorted($union->useWritePdo()->get()
            ->map(static fn (\stdClass $row): Reference => new Reference(self::text($row->authorizable_type), self::text($row->authorizable_id)))
            ->all());
    }

    /**
     * Return the query of the grantees of one grant table's live rows that meet
     * the condition and hold in the application.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $target
     * @param  \Closure(\Illuminate\Database\Query\Builder, string): void  $constrain
     * @param  string|null  $application
     * @return \Illuminate\Database\Query\Builder
     */
    private static function holdersIn(Connection $connection, GrantTarget $target, \Closure $constrain, ?string $application): Builder
    {
        $table = $target->table();
        $query = $connection->query()->from($table)->select([$table . '.authorizable_type', $table . '.authorizable_id']);

        LiveGrants::only($query, $table);

        if ($target === GrantTarget::POLICY) {
            /** @var class-string<\SineMacula\Laravel\Authorization\Models\Role> $role */
            $role = ModelClasses::get('role');

            InlinePolicies::attachedToTheirGrantee($query, $table);

            // A policy attached to a role is a grant to whoever holds the role,
            // listed through their own grant of it, never to the role.
            $query->where($table . '.authorizable_type', '<>', (new $role)->getMorphClass());
        }

        if ($application !== null) {
            GrantApplications::only($query, $table, $application);
        }

        $constrain($query, $table);

        return $query;
    }

    /**
     * Return a value read from a row as a string: a string as itself, anything
     * else as empty, as every grant table stores its grantee as strings.
     *
     * @param  mixed  $value
     * @return string
     */
    private static function text(mixed $value): string
    {
        return \is_string($value) ? $value : '';
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
