<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Concerns;

use Illuminate\Container\Container;
use SineMacula\Laravel\Authorization\Evaluation\CheckInput;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\HeldPermission;
use SineMacula\Laravel\Authorization\Exceptions\InvalidPreviewException;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\AuthorizationScope;
use SineMacula\Laravel\Authorization\Support\PermissionCatalogue;
use SineMacula\Laravel\Authorization\Support\PermissionDefinition;
use SineMacula\Laravel\Authorization\Support\ResourceReferences;

/**
 * The listings of the authorization manager: `permissionsFor()`, the actions a
 * subject may take in a scope (AUTHZ-10.4), and `heldPermissionsFor()`, the
 * same actions each with the authentication requirements its decision read
 * (N128, N129). Both list through the one path, so they list the same actions,
 * in the same order, and refuse, throw and record alike.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait ListsPermissions
{
    /**
     * Return the actions the subject may take in the scope (AUTHZ-10.4, N69),
     * for a UI to show or hide its controls: every action the permission
     * catalogue declares (the package's own permissions, the cases of the
     * configured enums and the definitions of the configured providers), each
     * name once, in the catalogue's order, whose `check()` on the scope's
     * resource, with the context, would allow, in the scope, about the subject.
     *
     * A resolved `Subject` is taken as it is, its identity, guard and session
     * kept; any other object is named as `for()` names it; and null is the
     * subject this manager's checks are about, as `check()` takes it: the
     * request's, or the one `for()` or `forUser()` named, so
     * `forUser(null)->permissionsFor(null, ...)` lists a guest's actions, which
     * are none. The scope's tenant and application are put in place of the
     * request's, both as the subject's and as the scope of the grants that
     * count, and the request's are restored once the actions are decided, even
     * when deciding one throws, with what the resolution cache held for them
     * (see `AuthorizationScope`). The scope given wins over the one a `Subject`
     * named through `for()` would decide in, as it does inside
     * `AuthorizationScope::within()`.
     *
     * The listing is exact: each action is decided through the one decision
     * path `checkMany()` takes, over what the checks share read once, the
     * resource's tenant and attributes among it, so its denies, conditions,
     * boundaries, guardrails, caps and authentication requirements are weighed
     * exactly as `check()` weighs them, never as the allows less the denies. An
     * action whose check would be `insufficient_authentication` is not listed,
     * and one whose check would throw makes the listing throw what it throws,
     * so nothing is ever listed that the check would not allow. A listing for
     * one resource can differ from a listing for none, and the action is still
     * to be authorized when it is taken.
     *
     * Listing is introspection, not a check (N70): it records no last decision
     * and dispatches no `DecisionEvaluated` and no `AuthorizationFailed`. The
     * break-glass reporting of BL-70 is to define how it treats it. A catalogue
     * that cannot be read, such as one declaring a name twice with different
     * metadata, throws `InvalidPermissionCatalogueException`.
     *
     * On a preview from `previewFor()`, the subject is the preview's target,
     * named by null alone: naming any subject, or a scope of another tenant or
     * application than the preview's, throws `InvalidPreviewException`. The
     * preview is admitted first, and each action it evaluates is reported with
     * `DecisionEvaluated` as `authorization.events.decisions` selects, every
     * one while `previews` is on, naming both parties, while the last decision
     * is left as the admission recorded it (N86).
     *
     * @param  object|null  $subject
     * @param  \SineMacula\Laravel\Authorization\Support\AuthorizationScope  $scope
     * @param  array<string, mixed>  $context
     * @return list<string>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AttributeProviderFailed
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidPermissionCatalogueException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidPreviewException
     *
     * @phpstan-ignore throws.unusedType
     */
    public function permissionsFor(?object $subject, AuthorizationScope $scope, array $context = []): array
    {
        $this->state?->ensureHealthy();

        return $this->listed('permissionsFor', $subject, $scope, $context, static fn (string $action): string => $action);
    }

    /**
     * Return the actions the subject may take in the scope, as
     * `permissionsFor()` lists them, each with the authentication requirements
     * its decision read (N128, N129): a `HeldPermission` for every action
     * `permissionsFor()` would list, given the same arguments, in the same
     * order, and none other.
     *
     * Each entry names every part of every authentication requirement its
     * decision read, on an allow or a deny, or in a further check the decision
     * made, met or not, and whether or not it decided the answer, once each,
     * sorted, so an entry naming none is held unconditionally, whatever the
     * session has proved, while one naming any may depend on the session's
     * authentication state as it is now (see `HeldPermission`). An audit of
     * what a subject holds lists for the real subject and session, and counts a
     * conditional entry as not held unconditionally.
     *
     * It is listed exactly as `permissionsFor()` lists: the subject is taken,
     * the scope put in place and the catalogue read the same way, an action
     * whose check would be `insufficient_authentication` is not listed, it
     * refuses and throws what `permissionsFor()` would, and it records no last
     * decision and dispatches no `DecisionEvaluated` and no
     * `AuthorizationFailed`, a preview's listing dispatching
     * `DecisionEvaluated` alone, as `authorization.events.decisions` selects
     * (N86).
     *
     * @param  object|null  $subject
     * @param  \SineMacula\Laravel\Authorization\Support\AuthorizationScope  $scope
     * @param  array<string, mixed>  $context
     * @return list<\SineMacula\Laravel\Authorization\Evaluation\HeldPermission>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AttributeProviderFailed
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidPermissionCatalogueException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidPreviewException
     *
     * @phpstan-ignore throws.unusedType
     */
    public function heldPermissionsFor(?object $subject, AuthorizationScope $scope, array $context = []): array
    {
        $this->state?->ensureHealthy();

        $held = static fn (string $action, Decision $decision): HeldPermission => new HeldPermission($action, $decision->requirementsRead);

        return $this->listed('heldPermissionsFor', $subject, $scope, $context, $held);
    }

    /**
     * Decide every action of the catalogue for the subject in the scope, as
     * `permissionsFor()` lists them, and return an entry for each action
     * allowed, in the catalogue's order, made from the action and its decision.
     * The method named is the listing a preview refuses a subject to.
     *
     * @template TEntry
     *
     * @param  string  $method
     * @param  object|null  $subject
     * @param  \SineMacula\Laravel\Authorization\Support\AuthorizationScope  $scope
     * @param  array<string, mixed>  $context
     * @param  \Closure(string, \SineMacula\Laravel\Authorization\Evaluation\Decision): TEntry  $entry
     * @return list<TEntry>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidPreviewException
     */
    private function listed(string $method, ?object $subject, AuthorizationScope $scope, array $context, \Closure $entry): array
    {
        $preview = $this->preview;

        if ($subject !== null && $preview !== null) {
            throw InvalidPreviewException::retargeted($method);
        }

        // A `Subject` named through `for()` is the subject the scoped manager
        // decides about, as it is.
        $named = $subject === null ? $this->currentSubject() : $this->for($subject)->currentSubject();

        $preview?->refuseOtherScope($scope);

        /** @var \SineMacula\Laravel\Authorization\Support\PermissionCatalogue $catalogue */
        $catalogue = Container::getInstance()->make(PermissionCatalogue::class);
        $actions   = \array_unique(\array_map(static fn (PermissionDefinition $definition): string => $definition->name, $catalogue->definitions()));

        $list = fn (?Subject $about): array => $scope->within(function () use ($about, $scope, $actions, $context, $preview, $entry): array {
            // Every action is decided on the one reference, so the resource is
            // told, and its attributes read, once for the listing.
            $resource  = ResourceReferences::of($scope->resource);
            $checks    = \array_map(static fn (string $action): CheckInput => new CheckInput($action, $resource, $context), $actions);
            $decisions = $this->batch($preview !== null, false)->decide($about, $checks);
            $allowed   = \array_filter($decisions, static fn (Decision $decision): bool => $decision->isAllowed());

            return \array_map(static fn (int $key): mixed => $entry($actions[$key], $allowed[$key]), \array_keys($allowed));
        });

        // A preview's target is already the subject of its scope, which is the
        // listing's.
        return $preview === null ? $list($scope->subjectIn($named)) : $preview->run($list);
    }
}
