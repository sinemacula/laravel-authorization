<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Hooks;

use Carbon\CarbonImmutable;
use Illuminate\Container\Container;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;
use SineMacula\Laravel\Authorization\Administration\OperationGrantee;
use SineMacula\Laravel\Authorization\Contracts\IdentityDirectory;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Enums\GrantTarget;
use SineMacula\Laravel\Authorization\Enums\WideningReason;
use SineMacula\Laravel\Authorization\Exceptions\UnresolvableRecipientException;
use SineMacula\Laravel\Authorization\Services\Support\GrantChanges;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\GrantRoots;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\TenantChain;

/**
 * Tells which of the grants a call proposes widen an identity's scope
 * (AUTHZ-11.3).
 *
 * A grant changes nothing, and is never classified, when the grantee already
 * holds it live in the same scope with the same reach or more, until the same
 * instant or later: a grant the grantee holds unchanged, or one that only
 * shortens it. Every other grant is evaluated: a new grant, the re-arm of one
 * that has expired, one that extends a live grant's expiry, and one that
 * reaches below its tenant where the live grant did not.
 *
 * An evaluated grant widens the scope of the identity behind its grantee when
 * its grantee is that identity, since it holds across every principal of it;
 * when it is platform-wide; when no live grant of the identity or of any of its
 * principals applied in its tenant before (one made there, one made at an
 * ancestor and reaching below it, or a platform-wide one), which covers a grant
 * in a new tenant, in a sibling of one held and at an ancestor of one held; and
 * when it reaches below its tenant where none of those grants reached below
 * before. The identity's principals are those the identity directory lists
 * (N81), and the grants are read by the grant scope query's reader, in every
 * application, on the write connection.
 *
 * When in doubt, the grant widens: an incomplete list of principals, or a tree
 * that cannot be read, is a reason of its own. An identity that cannot be
 * resolved, its grantee's model not found or the subject resolver naming no
 * identity for it, is refused with `UnresolvableRecipientException` rather than
 * classified. A grant that may widen authority is not the same as one that
 * widens the identity's scope: a permission added to a role the identity holds
 * in one tenant widens nothing here, whatever `Narrowing` says of it.
 *
 * Nothing is locked or pinned: every read is a plain read, so the
 * classification can run before the package takes any lock for the call.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class WideningClassifier
{
    /**
     * Return the widening of the grants the operation proposes for the grantee,
     * or null when none of them widens the identity's scope.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Operation  $operation
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  list<\SineMacula\Laravel\Authorization\Hooks\ProposedGrant>  $proposals
     * @return \SineMacula\Laravel\Authorization\Hooks\GrantWidening|null
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\UnresolvableRecipientException
     */
    public static function classify(Operation $operation, Model|Reference $grantee, array $proposals): ?GrantWidening
    {
        $now       = CarbonImmutable::now('UTC');
        $reference = Reference::of($grantee);
        $evaluated = \array_values(\array_filter($proposals, static fn (ProposedGrant $proposal): bool => self::isEvaluated($reference, $proposal, $now)));

        if ($evaluated === []) {
            return null;
        }

        [$identity, $isIdentity] = self::recipient($grantee);

        $widening = self::widening($identity, $reference, $isIdentity, $evaluated);

        return $widening === [] ? null : GrantWidening::of($operation, $identity, $reference, $widening, $now);
    }

    /**
     * Return the evaluated grants that widen the identity's scope, each with
     * its reasons.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $identity
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  bool  $isIdentity
     * @param  list<\SineMacula\Laravel\Authorization\Hooks\ProposedGrant>  $evaluated
     * @return list<\SineMacula\Laravel\Authorization\Hooks\ProposedGrant>
     */
    private static function widening(Reference $identity, Reference $grantee, bool $isIdentity, array $evaluated): array
    {
        $principals = self::directory()->principalsOf($identity);
        $roots      = new GrantRoots([$identity, $grantee, ...$principals->principals]);
        $doubts     = $principals->isComplete ? [] : [WideningReason::INCOMPLETE_DIRECTORY];
        $widening   = [];

        foreach ($evaluated as $proposal) {
            $reasons = [...($isIdentity ? [WideningReason::IDENTITY] : []), ...self::scopeReasons($proposal, $roots), ...$doubts];

            if ($reasons === []) {
                continue;
            }

            $widening[] = $proposal->withReasons($reasons);
        }

        return $widening;
    }

    /**
     * Return why the grant widens the identity's scope where it holds: it is
     * platform-wide; the tree cannot be read; no grant of the roots applied in
     * its tenant; or it reaches below its tenant, where none reached below.
     *
     * @param  \SineMacula\Laravel\Authorization\Hooks\ProposedGrant  $proposal
     * @param  \SineMacula\Laravel\Authorization\Support\GrantRoots  $roots
     * @return list<\SineMacula\Laravel\Authorization\Enums\WideningReason>
     */
    private static function scopeReasons(ProposedGrant $proposal, GrantRoots $roots): array
    {
        $chain = $proposal->tenant === null ? null : self::chainOf($proposal->tenant);

        return match (true) {
            $proposal->tenant === null                                             => [WideningReason::PLATFORM],
            $chain            === null                                             => [WideningReason::UNREADABLE_TREE],
            !$roots->appliesIn($chain)                                             => [WideningReason::NEW_TENANT],
            $proposal->includeSubtree && !$roots->appliesIn(self::belowOf($chain)) => [WideningReason::NEW_SUBTREE],
            default                                                                => [],
        };
    }

    /**
     * Determine whether the grant is evaluated: the grantee holds no live row
     * of it in its scope, or the grant reaches below where the row did not, or
     * expires later than the row. A grant the row holds unchanged, or one that
     * only shortens it, is not.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  \SineMacula\Laravel\Authorization\Hooks\ProposedGrant  $proposal
     * @param  \Carbon\CarbonImmutable  $now
     * @return bool
     */
    private static function isEvaluated(Reference $grantee, ProposedGrant $proposal, CarbonImmutable $now): bool
    {
        $kind = self::kindOf($proposal->action);
        $live = $kind === null ? null : GrantChanges::table($kind, $grantee, null, new GrantScope($proposal->tenant, $proposal->application, $proposal->includeSubtree))
            ->liveRow($proposal->target->id, Carbon::instance($now));

        if ($live === null) {
            return true;
        }

        [$expiresAt, $isBelow] = $live;

        return ($proposal->includeSubtree && !$isBelow) || self::isLater($proposal->expiresAt, $expiresAt);
    }

    /**
     * Determine whether the proposed expiry is later than the held one: never
     * expiring against a held expiry, or a later instant.
     *
     * @param  \DateTimeImmutable|null  $proposed
     * @param  \Illuminate\Support\Carbon|null  $held
     * @return bool
     */
    private static function isLater(?\DateTimeImmutable $proposed, ?Carbon $held): bool
    {
        return $held !== null && ($proposed === null || $proposed->getTimestamp() > $held->getTimestamp());
    }

    /**
     * Return the identity behind the grantee, and whether the grantee is that
     * identity rather than one of its principals, as the bound subject
     * resolver's `forUser()` makes a subject of the grantee's model; refuse a
     * grantee whose identity cannot be resolved.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @return array{\SineMacula\Laravel\Authorization\Support\Reference, bool}
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\UnresolvableRecipientException
     */
    private static function recipient(Model|Reference $grantee): array
    {
        $reference = Reference::of($grantee);
        $model     = $grantee instanceof Model ? $grantee : OperationGrantee::model($reference);

        $subject = $model === null ? null : self::rescued(
            static fn (): Subject => self::resolver()->forUser($model),
            static fn (\Throwable $exception): never => throw new UnresolvableRecipientException($reference, $exception),
        );

        $identity  = $subject?->identity instanceof Model && $subject->identity->exists ? Reference::of($subject->identity) : null;
        $isSubject = $subject?->subject instanceof Model  && self::isSame(Reference::of($subject->subject), $reference);

        return match (true) {
            $identity !== null && self::isSame($identity, $reference) => [$identity, true],
            $identity !== null && $isSubject                          => [$identity, false],
            default                                                   => throw new UnresolvableRecipientException($reference),
        };
    }

    /**
     * Return the chain of the tenant in the bound tree, read afresh, or null
     * when the tree cannot be read: the application's tree may fail in any way,
     * and a failure is a doubt, never a guess.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @return \SineMacula\Laravel\Authorization\Support\TenantChain|null
     */
    private static function chainOf(Reference $tenant): ?TenantChain
    {
        return self::rescued(static fn (): TenantChain => TenantChain::of($tenant, TenantChain::tree(), isFresh: true), static fn (): null => null);
    }

    /**
     * Return what the read returns or, when it throws, what the failure gives
     * for its exception: an application's resolver or tree may fail in any way.
     *
     * @template TRead
     * @template TFailed
     *
     * @param  \Closure(): TRead  $read
     * @param  \Closure(\Throwable): TFailed  $failed
     * @return TFailed|TRead
     */
    private static function rescued(\Closure $read, \Closure $failed): mixed
    {
        try {
            return $read();
        } catch (\Throwable $exception) {
            return $failed($exception);
        }
    }

    /**
     * Return the chain standing just below the chain's tenant, so a grant made
     * at the tenant counts only when it reaches below it.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\TenantChain  $chain
     * @return \SineMacula\Laravel\Authorization\Support\TenantChain
     */
    private static function belowOf(TenantChain $chain): TenantChain
    {
        return new TenantChain($chain->tenants, true);
    }

    /**
     * Return the kind of grant the action grants, or null for an action no
     * grant table answers.
     *
     * @param  string  $action
     * @return \SineMacula\Laravel\Authorization\Enums\GrantTarget|null
     */
    private static function kindOf(string $action): ?GrantTarget
    {
        foreach (GrantTarget::cases() as $kind) {
            if ($kind->grantAction() === $action) {
                return $kind;
            }
        }

        return null;
    }

    /**
     * Determine whether two references name the same record.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $left
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $right
     * @return bool
     */
    private static function isSame(Reference $left, Reference $right): bool
    {
        return $left->type === $right->type && $left->id === $right->id;
    }

    /**
     * Return the bound identity directory.
     *
     * @return \SineMacula\Laravel\Authorization\Contracts\IdentityDirectory
     */
    private static function directory(): IdentityDirectory
    {
        /** @var \SineMacula\Laravel\Authorization\Contracts\IdentityDirectory */
        return Container::getInstance()->make(IdentityDirectory::class);
    }

    /**
     * Return the bound subject resolver.
     *
     * @return \SineMacula\Laravel\Authorization\Contracts\SubjectResolver
     */
    private static function resolver(): SubjectResolver
    {
        /** @var \SineMacula\Laravel\Authorization\Contracts\SubjectResolver */
        return Container::getInstance()->make(SubjectResolver::class);
    }
}
