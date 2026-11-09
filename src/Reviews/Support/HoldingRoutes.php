<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Reviews\Support;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Query\Builder;
use SineMacula\Laravel\Authorization\Contracts\IdentityDirectory;
use SineMacula\Laravel\Authorization\Enums\GrantTarget;
use SineMacula\Laravel\Authorization\Reviews\Enums\SourceKind;
use SineMacula\Laravel\Authorization\Reviews\ReviewQuery;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\InlinePolicies;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\SubjectGrants;

/**
 * What a subject holds in a review's scope, and where (N93), one row for each
 * route: each role granted, and each role above it it inherits; each permission
 * granted, and each one a role of its chain carries; each policy attached, and
 * each one attached to a role of its chain where both hold.
 *
 * In principal mode the grants read are the principal's own and its identity's
 * when they reach it (another model of the same kind, see
 * `SubjectGrants::grantingIdentity()`), a row through the identity naming it as
 * the grantee and as `via_identity`; a sibling principal's never are. In
 * identity mode they are the identity's and those of every principal the
 * identity directory lists, each row naming its actual grantee, and the review
 * is incomplete when the directory says its list may leave one out.
 *
 * One subject's grants are read whole, then sorted into the review's order: in
 * a fixed number of queries for a principal, and for an identity a chunk of its
 * principals at a time (see `GrantRows::CHUNK`), so no query's bindings grow
 * with its principals. Whether its role grants meet the policies attached to
 * their roles is settled in a fixed number of queries (see
 * `ReviewRun::settle()`), never one for each tenant a grant is held in.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class HoldingRoutes
{
    /**
     * Collect the rows of what the query's subject holds, and return whether
     * every grantee it reads was known.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\Support\ReviewRun  $run
     * @param  \SineMacula\Laravel\Authorization\Reviews\ReviewQuery  $query
     * @param  \SineMacula\Laravel\Authorization\Reviews\Support\RowCollector  $rows
     * @param  \SineMacula\Laravel\Authorization\Contracts\IdentityDirectory  $directory
     * @return bool
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException
     */
    public static function read(ReviewRun $run, ReviewQuery $query, RowCollector $rows, IdentityDirectory $directory): bool
    {
        [$subject, $grantees, $via, $isComplete] = self::granteesOf($query, $directory);

        self::throughRoles($run, $rows, $subject, $grantees, $via);
        self::direct($run, $rows, GrantTarget::PERMISSION, $subject, $grantees, $via);
        self::direct($run, $rows, GrantTarget::POLICY, $subject, $grantees, $via);

        return $isComplete;
    }

    /**
     * Collect the routes of the roles granted: each role, the roles above it,
     * and what each of them carries.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\Support\ReviewRun  $run
     * @param  \SineMacula\Laravel\Authorization\Reviews\Support\RowCollector  $rows
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $subject
     * @param  list<\SineMacula\Laravel\Authorization\Support\Reference>  $grantees
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $via
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException
     */
    private static function throughRoles(ReviewRun $run, RowCollector $rows, Reference $subject, array $grantees, ?Reference $via): void
    {
        $grants = self::grantsOf($run, GrantTarget::ROLE, $grantees);
        $chains = RoleChains::above($run, \array_values(\array_unique(\array_map(static fn (GrantRow $grant): string => $grant->targetId, $grants))));
        $roles  = \array_values(\array_unique(\array_merge([], ...\array_values($chains))));

        $edges       = RoleCarriers::edges($run, $roles);
        $attachments = RoleCarriers::attachments($run, $roles);
        $type        = Definitions::morph(GrantTarget::ROLE);

        $run->settle($grants, $attachments);

        foreach ($grants as $grant) {
            $chain   = $chains[$grant->targetId] ?? [];
            $through = self::isThrough($grant, $via) ? $via : null;

            foreach ($chain as $depth => $role) {
                $kind = $depth === 0 ? SourceKind::ROLE_GRANT : SourceKind::ROLE_INHERITED;

                $rows->route($kind, $subject, $grant, new Reference($type, $role), \array_slice($chain, 0, $depth + 1), [], $through);
            }

            if ($chain === []) {
                continue;
            }

            RoleCarriers::throughEdges($rows, $subject, $grant, $chain, $edges, $through);
            RoleCarriers::throughAttachments($run, $rows, $subject, $grant, $chain, $attachments, $through);
        }
    }

    /**
     * Collect the direct grants of the kind, a permission or a policy, each one
     * route.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\Support\ReviewRun  $run
     * @param  \SineMacula\Laravel\Authorization\Reviews\Support\RowCollector  $rows
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $kind
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $subject
     * @param  list<\SineMacula\Laravel\Authorization\Support\Reference>  $grantees
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $via
     * @return void
     */
    private static function direct(ReviewRun $run, RowCollector $rows, GrantTarget $kind, Reference $subject, array $grantees, ?Reference $via): void
    {
        $type   = Definitions::morph($kind);
        $source = $kind === GrantTarget::POLICY ? SourceKind::POLICY_ATTACHMENT : SourceKind::PERMISSION_GRANT;

        foreach (self::grantsOf($run, $kind, $grantees) as $grant) {
            $rows->route($source, $subject, $grant, new Reference($type, $grant->targetId), [], [], self::isThrough($grant, $via) ? $via : null);
        }
    }

    /**
     * Return the grantees' live grants of the kind in the review's scope, of
     * definitions the reviewed tenant sees, a policy's only where an inline
     * policy is attached to its own grantee, read a chunk of the grantees at a
     * time.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\Support\ReviewRun  $run
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $kind
     * @param  list<\SineMacula\Laravel\Authorization\Support\Reference>  $grantees
     * @return list<\SineMacula\Laravel\Authorization\Reviews\Support\GrantRow>
     */
    private static function grantsOf(ReviewRun $run, GrantTarget $kind, array $grantees): array
    {
        $table = $kind->table();

        return GrantRows::allOf($grantees, static function (array $chunk) use ($run, $kind, $table): Builder {
            $query = $run->visible(GrantRows::grantedTo($run->live($run->constrain(GrantRows::of($kind), $table), $table), $table, $chunk), $kind, $table . '.' . $kind->column());

            return $kind === GrantTarget::POLICY ? InlinePolicies::attachedToTheirGrantee($query, $table) : $query;
        }, $kind->value);
    }

    /**
     * Return whom the rows are about, the grantees whose grants are read, the
     * identity a grant reaches the subject through, and whether the grantees
     * are all known: in principal mode the principal, with its identity when it
     * grants to it; in identity mode the identity, with every principal the
     * directory lists.
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @formatter:off
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\ReviewQuery  $query
     * @param  \SineMacula\Laravel\Authorization\Contracts\IdentityDirectory  $directory
     * @return array{0: \SineMacula\Laravel\Authorization\Support\Reference, 1: list<\SineMacula\Laravel\Authorization\Support\Reference>, 2: \SineMacula\Laravel\Authorization\Support\Reference|null, 3: bool}
     *
     * @throws \UnexpectedValueException
     *
     * @formatter:on
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     */
    private static function granteesOf(ReviewQuery $query, IdentityDirectory $directory): array
    {
        $about = $query->about() ?? throw new \UnexpectedValueException('A review of holdings names its subject.');

        if ($query->subject === null) {
            $principals = $directory->principalsOf($about);

            return [$about, [$about, ...$principals->principals], null, $principals->isComplete];
        }

        $identity = self::grantingIdentity($query->subject);
        $isOther  = $identity !== null && ($identity->type !== $about->type || $identity->id !== $about->id);

        return [$about, $isOther ? [$about, $identity] : [$about], $isOther ? $identity : null, true];
    }

    /**
     * Return the reference to the subject's identity when it grants to the
     * subject and is a model or reference; null otherwise.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @return \SineMacula\Laravel\Authorization\Support\Reference|null
     */
    private static function grantingIdentity(Subject $subject): ?Reference
    {
        $identity = SubjectGrants::grantingIdentity($subject);

        return $identity instanceof Model || $identity instanceof Reference ? Reference::of($identity) : null;
    }

    /**
     * Determine whether the grant reaches the subject through the identity: it
     * names the identity as its grantee.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\Support\GrantRow  $grant
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $via
     * @return bool
     */
    private static function isThrough(GrantRow $grant, ?Reference $via): bool
    {
        return $via !== null && $grant->grantee->type === $via->type && $grant->grantee->id === $via->id;
    }
}
