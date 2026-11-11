<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Preview;

use SineMacula\Laravel\Authorization\Administration\ActingContext;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\DecisionMemory;
use SineMacula\Laravel\Authorization\Exceptions\AuthorizationException;
use SineMacula\Laravel\Authorization\Exceptions\InsufficientAuthenticationException;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * The admissions of one use of a preview (N84): each check, each batch, each
 * listing and each compile of a query scoped through the preview is one use,
 * and is admitted wherever one of its decisions is made.
 *
 * A decision about the target is made where `ResourceScope` puts it: in the
 * preview's scope, in the tenant of a resource of that scope's subtree, a child
 * tenant's included, or just below it, or at platform scope for a resource
 * admitted from outside; a further check and a query's class of rows are made
 * where they are asked. Before the target's sources are gathered in such a
 * scope (see `Previewing::admit()`), the previewer is decided
 * `authorization:subject.preview` on the preview resource of that scope, its
 * tenant, its application and whether it is decided just below the tenant (see
 * `PreviewResource`), through its own manager, with its session, denies,
 * boundaries, guardrails and caps, in that scope, so a deny the previewer holds
 * in a tenant refuses every answer made there. That is an ordinary check,
 * recorded and reported as any is: a refusal throws `AuthorizationException`,
 * carrying the previewer's decision, and no decision about the target is made
 * in that scope, nor any after it in the use. A preview distributes no
 * authority, so nothing beyond the ordinary check is weighed: a deny,
 * conditional or not, refuses only where it applies, and a policy on the
 * preview resource's attributes restricts who may be previewed, and where. No
 * rank rule applies.
 *
 * Each scope is admitted once in the use, keyed as the resolution cache keys a
 * scope, by its tenant, whether it is decided just below it, and its
 * application, so a batch over many resources costs one admission per scope its
 * decisions are made in, not one per resource. Nothing is kept from one use to
 * the next: a right revoked meanwhile refuses the next use. Once the decisions
 * are forgotten (see `DecisionMemory`), the use admits each scope again, at its
 * next decision there.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class PreviewAdmission
{
    /** @var array<string, bool> The scopes the use is admitted in, each true, by the key of the scope. */
    private array $admitted = [];

    /** @var int|null The generation of the decisions the admissions were made in (see `DecisionMemory`), or null before any is. */
    private ?int $generation = null;

    /**
     * Create the admissions of a use, none made yet.
     *
     * @param  \SineMacula\Laravel\Authorization\AuthorizationManager  $admitter
     * @param  \SineMacula\Laravel\Authorization\Preview\PreviewResource  $resource
     */
    public function __construct(

        /** The previewer's own manager, which decides each admission. */
        private readonly AuthorizationManager $admitter,

        /** The preview resource naming the target, put in each scope admitted. */
        private readonly PreviewResource $resource,
    ) {}

    /**
     * Admit the use in the scope in place, once: decide the previewer the right
     * on the preview resource of the scope, and throw `AuthorizationException`,
     * carrying that decision, when it is not allowed, a step-up the right needs
     * included.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InsufficientAuthenticationException
     */
    public function admitHere(): void
    {
        $generation = DecisionMemory::current()->generation();

        // Made before the decisions were forgotten, made again.
        if ($generation !== $this->generation) {
            $this->admitted   = [];
            $this->generation = $generation;
        }

        $key = TenantScope::scopeKey();

        if ($this->admitted[$key] ?? false) {
            return;
        }

        $tenant      = TenantScope::currentTenant();
        $application = TenantScope::currentApplication();
        $resource    = $this->resource->in($tenant === null ? null : new Reference(...$tenant), $application, TenantScope::isBelowTenant());

        $this->authorize($resource);

        $this->admitted[$key] = true;
    }

    /**
     * Return the previewer, the subject the previewer's manager decides about.
     *
     * @return \SineMacula\Laravel\Authorization\Subject|null
     */
    public function previewer(): ?Subject
    {
        return $this->admitter->currentSubject();
    }

    /**
     * Decide the previewer the right on the preview resource, recorded and
     * reported as `authorize()` records and reports a refusal, and throw
     * `AuthorizationException` when it is not allowed: a step-up the right
     * needs is refused as any other denial, carrying the decision that asked
     * for it.
     *
     * @param  \SineMacula\Laravel\Authorization\Preview\PreviewResource  $resource
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InsufficientAuthenticationException
     */
    private function authorize(PreviewResource $resource): void
    {
        try {
            $this->admitter->authorize(PackagePermissions::SUBJECT_PREVIEW, $resource);
        } catch (InsufficientAuthenticationException $exception) {
            throw self::refusal($exception->getDecision() ?? throw $exception);
        }
    }

    /**
     * Return the refusal the decision makes, an `AuthorizationException` with
     * its reason and the one `denied` line, carrying the decision.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Decision  $decision
     * @return \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    private static function refusal(Decision $decision): AuthorizationException
    {
        return ActingContext::refusal($decision);
    }
}
