<?php

declare(strict_types = 1);

namespace Tests\Feature\ForgettingDecisions;

use Illuminate\Contracts\Events\Dispatcher;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Evaluation\CheckInput;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Events\DecisionEvaluated;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Preview\PreviewAdmission;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use Tests\Concerns\PreviewsSubjects;
use Tests\Concerns\ReportsEveryDecision;
use Tests\TestCase;

/**
 * Feature tests for a preview's use when the decisions of the request are
 * forgotten while it runs (N112): its scope, admitted once in the use until
 * then, is admitted again at its next decision there, and once only.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PreviewAdmission::class)]
final class PreviewAdmissionTest extends TestCase
{
    use PreviewsSubjects, ReportsEveryDecision;

    /**
     * Report every decision, allows included: these tests observe the decisions
     * each call makes.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->reportEveryDecision();
    }

    /**
     * A batch previewed over three checks of one scope is admitted once, and
     * once more after the decisions are forgotten following its first check;
     * every check is still decided about the target.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAScopeIsAdmittedAgainOnceTheDecisionsAreForgotten(): void
    {
        $preview  = $this->signIn(self::previewer())->previewFor(self::target());
        $reported = ['admissions' => 0, 'decisions' => 0];

        $this->container()->make(Dispatcher::class)->listen(DecisionEvaluated::class, static function (DecisionEvaluated $event) use (&$reported): void {
            if ($event->previewer === null) {
                $reported['admissions'] += $event->action === PackagePermissions::SUBJECT_PREVIEW ? 1 : 0;

                return;
            }

            if (++$reported['decisions'] !== 1) {
                return;
            }

            Authorization::forgetDecisionsFor();
        });

        $decisions = $preview->checkMany(\array_fill(0, 3, new CheckInput('posts:read')));

        self::assertSame([true, true, true], \array_map(static fn (Decision $decision): bool => $decision->isAllowed(), $decisions));
        self::assertSame(['admissions' => 2, 'decisions' => 3], $reported);
    }
}
