<?php

declare(strict_types = 1);

namespace Tests\Feature\Preview;

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Blade;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Gate;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authorization\Administration\ActingContext;
use SineMacula\Laravel\Authorization\Concerns\BuildsScopedManagers;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Policy as EvaluationPolicy;
use SineMacula\Laravel\Authorization\Events\DecisionEvaluated;
use SineMacula\Laravel\Authorization\Exceptions\AuthorizationException;
use SineMacula\Laravel\Authorization\Exceptions\InvalidPreviewException;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Support\BladeHelpers;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\PreviewsSubjects;
use Tests\Concerns\ReadsDispatchedEvents;
use Tests\Feature\Stubs\AuthenticatableIdentity;
use Tests\TestCase;

/**
 * Feature tests for `previewFor()`, the preview clone of the authorization
 * manager (AUTHZ-11.4): it is admitted as it is built, keeps its two parties
 * and its scope, and leaves the caller, the facade, the Gate and Blade as they
 * were.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversTrait(BuildsScopedManagers::class)]
final class BuildsScopedManagersTest extends TestCase
{
    use PreviewsSubjects, ReadsDispatchedEvents;

    /**
     * Building a preview admits it at once, a check about the caller recorded
     * and reported as any check is, and returns a clone, the manager it was
     * built from unchanged.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    public function testAPreviewIsAdmittedAsItIsBuilt(): void
    {
        Event::fake([DecisionEvaluated::class]);

        $caller  = self::previewer();
        $target  = self::target();
        $manager = $this->signIn($caller);
        $preview = $manager->previewFor($target);
        $events  = self::dispatchedEvents(DecisionEvaluated::class);

        self::assertNotSame($manager, $preview);
        self::assertCount(1, $events);
        self::assertSame(PackagePermissions::SUBJECT_PREVIEW, $events[0]->action);
        self::assertEquals(Reference::of($caller), $events[0]->subject);
        self::assertTrue($manager->lastDecision()?->isAllowed());
        self::assertSame($caller, $manager->currentSubject()?->subject);
        self::assertSame($target, $preview->currentSubject()?->subject);
    }

    /**
     * The admission made as the preview is built is evaluated as the preview
     * is: a listener on it cannot build an acting context.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    public function testTheAdmissionAsItIsBuiltConfersNoAuthority(): void
    {
        $caller  = self::previewer();
        $target  = self::target();
        $manager = $this->signIn($caller);
        /** @var \ArrayObject<int, \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason> $refused */
        $refused = new \ArrayObject;

        Event::listen(DecisionEvaluated::class, static function () use ($refused): void {
            try {
                ActingContext::current();
            } catch (AuthorizationException $exception) {
                $refused[] = $exception->getReason();
            }
        });

        $manager->previewFor($target);

        self::assertSame([DecisionReason::ADMINISTRATION_PREVIEWING], $refused->getArrayCopy());
    }

    /**
     * A preview cannot change its target, nor decide through hypothetical
     * policies or without the target's session caps, and a manager carrying a
     * policy override, or deciding without session caps, cannot be previewed
     * from.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    public function testRetargetingAndPolicyOverridesAreRefused(): void
    {
        $caller   = self::previewer();
        $target   = self::target();
        $manager  = $this->signIn($caller);
        $preview  = $manager->previewFor($target);
        $policies = [EvaluationPolicy::fromArray(['name' => 'anything', 'statements' => [['effect' => 'allow', 'actions' => ['*']]]])];

        $refusals = [
            'for'                => static fn (): mixed => $preview->for($caller),
            'forUser'            => static fn (): mixed => $preview->forUser($caller),
            'previewFor'         => static fn (): mixed => $preview->previewFor($caller),
            'withPolicies'       => static fn (): mixed => $preview->withPolicies($policies),
            'withoutSessionCaps' => static fn (): mixed => $preview->withoutSessionCaps(),
            'overridden'         => static fn (): mixed => $manager->withPolicies($policies)->previewFor($target),
            'sessionless'        => static fn (): mixed => $manager->withoutSessionCaps()->previewFor($target),
        ];
        $named = ['overridden' => 'withPolicies', 'sessionless' => 'withoutSessionCaps'];

        foreach ($refusals as $name => $refusal) {
            try {
                $refusal();
                self::fail("{$name}() was not refused.");
            } catch (InvalidPreviewException $exception) {
                self::assertStringContainsString($named[$name] ?? $name, $exception->getMessage());
            }
        }
    }

    /**
     * A cap on a preview caps the target's checks alone: the caller's admission
     * is still decided as the caller's own, so a cap that does not name the
     * right to preview never refuses it, and one on the caller's manager still
     * caps the admission.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    public function testACapOnAPreviewCapsTheTargetAlone(): void
    {
        $caller  = self::previewer();
        $target  = self::target('target', ['posts:read', 'posts:edit']);
        $manager = $this->signIn($caller);
        $capped  = $manager->previewFor($target)->capped(['posts:read']);

        self::assertTrue($capped->can('posts:read'));
        self::assertSame(DecisionReason::SESSION_POLICY, $capped->check('posts:edit')->reason);

        try {
            $manager->capped(['posts:*'])->previewFor($target);
            self::fail('A capped caller previewed.');
        } catch (AuthorizationException $exception) {
            self::assertSame(DecisionReason::SESSION_POLICY, $exception->getReason());
        }
    }

    /**
     * The Gate, Blade, the facade and the guard stay the caller's while a
     * preview is built and used, and while it is evaluated: only the preview
     * decides about the target.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    public function testTheGateBladeAndTheGuardStayTheCallers(): void
    {
        $caller = AuthenticatableIdentity::query()->create(['id' => 'signed-in']);
        $target = self::target();

        $caller->givePermission(self::permission(PackagePermissions::SUBJECT_PREVIEW));

        $this->actingAs($caller);

        $preview = Authorization::previewFor($target);
        $during  = [];

        Event::listen(DecisionEvaluated::class, static function (DecisionEvaluated $event) use (&$during): void {
            if ($event->previewer === null) {
                return;
            }

            $during[] = [Gate::allows('posts:read'), Authorization::currentSubject()?->subject];
        });

        self::assertTrue($preview->can('posts:read'));
        self::assertSame([[false, $caller]], $during);
        self::assertFalse(Gate::allows('posts:read'));
        self::assertSame('signed-in', Auth::id());
        self::assertSame($caller, Authorization::currentSubject()?->subject);
        self::assertSame($caller, BladeHelpers::currentSubject()?->subject);
        self::assertSame('no', \trim(Blade::render('@can(\'posts:read\') yes @else no @endcan')));
    }
}
