<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Evaluation\CheckInput;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Preview\PreviewContext;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResourceReference;
use Tests\Concerns\PreviewsSubjects;
use Tests\Feature\Stubs\StubTenant;
use Tests\Fixtures\QueryScoping\ClosureTenantTree;
use Tests\TestCase;

/**
 * Query budget of a preview batch: each use sets the request's memo aside and
 * moves between the scopes its decisions are made in, yet a batch over many
 * resources costs the queries one resource in each of its scopes costs.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PreviewContext::class)]
final class PreviewQueryBudgetTest extends TestCase
{
    use PreviewsSubjects;

    /**
     * A preview batch over a hundred resources alternating between a tenant and
     * its child costs the queries a batch of one in each costs.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPreviewBatchCostsWhatOneResourcePerScopeCosts(): void
    {
        $parent = StubTenant::query()->create(['id' => 'parent', 'name' => 'parent']);
        $child  = StubTenant::query()->create(['id' => 'child', 'name' => 'child']);

        $this->app?->instance(TenantTree::class, new ClosureTenantTree);

        ClosureTenantTree::add(Reference::of($parent));
        ClosureTenantTree::add(Reference::of($child), Reference::of($parent));

        $preview = $this->signIn(self::previewer(), 'session-1', $parent)->previewFor(self::target());
        $tenants = [Reference::of($parent), Reference::of($child)];
        $checks  = static fn (int $count): array => \array_map(
            static fn (int $key): CheckInput => new CheckInput('posts:read', ResourceReference::record('post', (string) $key, $tenants[$key % 2])),
            \range(0, $count - 1),
        );

        self::queriesOf($preview, $checks(2));

        [$two]               = self::queriesOf($preview, $checks(2));
        [$hundred, $allowed] = self::queriesOf($preview, $checks(100));

        self::assertNotSame([], $two);
        self::assertCount(\count($two), $hundred, "A hundred resources cost other queries than two:\n" . \implode("\n", $hundred));
        self::assertSame(\array_fill(0, 100, true), $allowed);
    }

    /**
     * Return the queries the preview's batch over the checks runs, and whether
     * each check is allowed.
     *
     * @param  \SineMacula\Laravel\Authorization\AuthorizationManager  $preview
     * @param  list<\SineMacula\Laravel\Authorization\Evaluation\CheckInput>  $checks
     * @return array{list<string>, list<bool>}
     */
    private static function queriesOf(AuthorizationManager $preview, array $checks): array
    {
        DB::flushQueryLog();
        DB::enableQueryLog();

        try {
            $decisions = $preview->checkMany($checks);
        } finally {
            DB::disableQueryLog();
        }

        return [\array_column(DB::getQueryLog(), 'query'), \array_values(\array_map(static fn (Decision $decision): bool => $decision->isAllowed(), $decisions))];
    }
}
