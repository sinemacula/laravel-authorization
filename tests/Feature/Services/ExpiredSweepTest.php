<?php

declare(strict_types = 1);

namespace Tests\Feature\Services;

use Illuminate\Database\Query\Builder;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Enums\GrantTarget;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Services\Support\ExpiredSweep;
use SineMacula\Laravel\Authorization\Support\Operation;
use Tests\TestCase;

/**
 * Feature tests for `ExpiredSweep`: the rows a query reads swept a chunk at a
 * time, each chunk one operation.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ExpiredSweep::class)]
final class ExpiredSweepTest extends TestCase
{
    /** @var list<array{list<string>, string, \SineMacula\Laravel\Authorization\Enums\GrantTarget|null}> Each chunk removed: its rows' names, its operation's id and the kind given. */
    private array $chunks = [];

    /**
     * The rows are swept a chunk at a time, with the columns, each chunk its
     * own operation handed the kind, until a chunk comes back short, and how
     * many were removed is returned.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSweepsAChunkAtATimeUntilAChunkIsShort(): void
    {
        self::permissions(5);

        self::assertSame(5, (new ExpiredSweep($this->removal(...), GrantTarget::ROLE))->run(self::expired(), ['name'], 2));

        self::assertSame([['expired-0', 'expired-1'], ['expired-2', 'expired-3'], ['expired-4']], \array_column($this->chunks, 0));
        self::assertCount(3, \array_unique(\array_column($this->chunks, 1)));
        self::assertSame([GrantTarget::ROLE, GrantTarget::ROLE, GrantTarget::ROLE], \array_column($this->chunks, 2));
        self::assertSame(0, self::expired()->count());
    }

    /**
     * A sweep whose last chunk is full reads once more and finds nothing, and
     * hands no kind when given none.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFullLastChunkIsFollowedByAnEmptyOne(): void
    {
        self::permissions(4);

        self::assertSame(4, (new ExpiredSweep($this->removal(...)))->run(self::expired(), ['name'], 2));

        self::assertSame([['expired-0', 'expired-1'], ['expired-2', 'expired-3'], []], \array_column($this->chunks, 0));
        self::assertSame([null, null, null], \array_column($this->chunks, 2));
    }

    /**
     * Remove the chunk's rows, recording the chunk, and return how many were
     * removed.
     *
     * @param  list<array<string, mixed>>  $rows
     * @param  \SineMacula\Laravel\Authorization\Support\Operation  $operation
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget|null  $kind
     * @return int
     */
    private function removal(array $rows, Operation $operation, ?GrantTarget $kind): int
    {
        /** @var list<string> $names */
        $names = \array_column($rows, 'name');

        $this->chunks[] = [$names, $operation->id, $kind];

        return DB::table('permissions')->whereIn('name', $names)->delete();
    }

    /**
     * Create the given number of permissions for the sweep to remove.
     *
     * @param  int  $count
     * @return void
     */
    private static function permissions(int $count): void
    {
        for ($index = 0; $index < $count; $index++) {
            Permission::create(['name' => 'expired-' . $index]);
        }
    }

    /**
     * Query the permissions the sweep removes, in name order.
     *
     * @return \Illuminate\Database\Query\Builder
     */
    private static function expired(): Builder
    {
        return DB::table('permissions')->where('name', 'like', 'expired-%')->orderBy('name');
    }
}
