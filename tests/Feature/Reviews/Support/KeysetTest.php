<?php

declare(strict_types = 1);

namespace Tests\Feature\Reviews\Support;

use Illuminate\Database\Query\Builder;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Enums\GrantTarget;
use SineMacula\Laravel\Authorization\Reviews\ReviewScope;
use SineMacula\Laravel\Authorization\Reviews\Support\GrantRow;
use SineMacula\Laravel\Authorization\Reviews\Support\GrantRows;
use SineMacula\Laravel\Authorization\Reviews\Support\Keyset;
use SineMacula\Laravel\Authorization\Reviews\Support\ReviewRun;
use Tests\Concerns\ReviewsAccess;
use Tests\TestCase;

/**
 * Feature tests for the keyset a review resumes from: from every row of a table
 * ordered as a review orders it, the rows after it, or from it, are exactly
 * those that follow it, over rows sharing every column but one, each nullable
 * column null or not, both reaches, and keys differing only in case, a trailing
 * space or accents, on every database.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(Keyset::class)]
final class KeysetTest extends TestCase
{
    use ReviewsAccess;

    /**
     * From each row, the rows after it are those that follow it in the order,
     * and the rows from it are it and those.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEveryRowResumesAtTheRowsThatFollowIt(): void
    {
        $role = self::role('reviewed');
        $rows = [];
        $now  = now()->utc()->format('Y-m-d H:i:s');

        foreach (['a', 'a ', 'A', "\u{e4}"] as $grantee) {
            foreach ([[null, null], ['tenant', null], [null, 't'], ['tenant', 't'], ['tenant', 'T']] as [$type, $id]) {
                foreach ([null, 'web'] as $application) {
                    $rows[] = [
                        'role_id'           => $role->getKey(),
                        'authorizable_type' => 'u',
                        'authorizable_id'   => $grantee,
                        'tenant_type'       => $type,
                        'tenant_id'         => $id,
                        'include_subtree'   => $id !== 'T',
                        'application'       => $application,
                        'created_at'        => $now,
                        'updated_at'        => $now,
                    ];
                }
            }
        }

        foreach (\array_chunk($rows, 20) as $chunk) {
            DB::table('authorizable_roles')->insert($chunk);
        }

        $table   = GrantTarget::ROLE->table();
        $ordered = static fn (): Builder => GrantRows::ordered(GrantRows::held(ReviewRun::of(ReviewScope::everywhere()), GrantTarget::ROLE), $table, 'role_id');
        $all     = GrantRows::page($ordered(), 'role', 1000);
        $keys    = \array_map(static fn (GrantRow $row): string => $row->key(), $all);

        self::assertCount(\count($rows), \array_unique($keys));

        foreach ($all as $index => $row) {
            $position = GrantRows::positionOf($row, true);

            self::assertSame(\array_slice($keys, $index + 1), self::keysOf(GrantRows::after($ordered(), $table, 'role_id', true, $position)), "after row {$index}");
            self::assertSame(\array_slice($keys, $index), self::keysOf(GrantRows::after($ordered(), $table, 'role_id', true, $position, true)), "from row {$index}");
        }
    }

    /**
     * A boolean column orders false before true: after true, nothing at that
     * prefix follows; after false, true does.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testABooleanOrdersFalseBeforeTrue(): void
    {
        $role = self::role('reviewed');

        self::grants()->grantRole(self::identity('ann'), $role, tenant: self::tenant('t'), includeSubtree: false);
        self::grants()->grantRole(self::identity('bob'), $role, tenant: self::tenant('t'));

        $column = GrantTarget::ROLE->table() . '.include_subtree';
        $flag   = static fn (bool $value, bool $isInclusive = false): array => \array_map(
            static fn (GrantRow $row): string => $row->grantee->id,
            GrantRows::page(Keyset::after(GrantRows::of(GrantTarget::ROLE)->orderBy($column), [[$column, Keyset::FLAG]], [$value], $isInclusive), 'role', 10),
        );

        self::assertSame(['bob'], $flag(false));
        self::assertSame([], $flag(true));
        self::assertSame(['bob'], $flag(true, true));
        self::assertSame(['ann', 'bob'], $flag(false, true));
    }

    /**
     * A position that does not hold one value for each column, a nullable
     * column taking its tag and its value, is refused.
     *
     * @return void
     */
    public function testAPositionOfTheWrongLengthIsRefused(): void
    {
        $table = GrantTarget::ROLE->table();

        $this->expectException(\UnexpectedValueException::class);

        Keyset::after(GrantRows::of(GrantTarget::ROLE), [[$table . '.tenant_type', Keyset::TAGGED]], [1]);
    }

    /**
     * Return the keys of the stored rows the query reads, in its order.
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @return list<string>
     */
    private static function keysOf(Builder $query): array
    {
        return \array_map(static fn (GrantRow $row): string => $row->key(), GrantRows::page($query, 'role', 1000));
    }
}
