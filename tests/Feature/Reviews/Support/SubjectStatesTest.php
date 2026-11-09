<?php

declare(strict_types = 1);

namespace Tests\Feature\Reviews\Support;

use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Reviews\Enums\GrantState;
use SineMacula\Laravel\Authorization\Reviews\Enums\SourceKind;
use SineMacula\Laravel\Authorization\Reviews\Enums\SubjectState;
use SineMacula\Laravel\Authorization\Reviews\ReviewRow;
use SineMacula\Laravel\Authorization\Reviews\Support\ReviewOrder;
use SineMacula\Laravel\Authorization\Reviews\Support\SubjectStates;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Feature\Stubs\NumberedIdentity;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\SuspendableIdentity;
use Tests\Fixtures\Reviews\NamedInactiveIdentity;
use Tests\TestCase;

/**
 * Feature tests for what a review knows of its rows' subjects: read by type in
 * one query each, inactive when deleted softly or reporting so, unknown when
 * gone or of no model, or as the resolved subject given.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(SubjectStates::class)]
final class SubjectStatesTest extends TestCase
{
    /**
     * Each subject is read by its morph type, in one query for each type,
     * outside every global scope.
     *
     * @return void
     */
    public function testEachSubjectIsReadByItsType(): void
    {
        $deleted = NumberedIdentity::query()->create(['name' => 'deleted']);
        $kept    = NumberedIdentity::query()->create(['name' => 'kept']);

        StubIdentity::query()->create(['id' => 'active']);
        NamedInactiveIdentity::query()->create(['id' => 'inactive', 'name' => 'inactive']);

        $deleted->delete();

        $subjects = [
            Reference::of($deleted),
            Reference::of($kept),
            new Reference((new StubIdentity)->getMorphClass(), 'active'),
            new Reference((new StubIdentity)->getMorphClass(), 'gone'),
            new Reference((new NamedInactiveIdentity)->getMorphClass(), 'inactive'),
            new Reference('no model', 'x'),
        ];

        $queries = 0;

        DB::listen(static function (QueryExecuted $query) use (&$queries): void {
            $queries++;
        });

        $states = SubjectStates::of($subjects);

        self::assertSame(3, $queries);
        self::assertSame(SubjectState::INACTIVE, $states[self::key(Reference::of($deleted))]);
        self::assertSame(SubjectState::ACTIVE, $states[self::key(Reference::of($kept))]);
        self::assertSame(SubjectState::ACTIVE, $states[self::key($subjects[2])]);
        self::assertArrayNotHasKey(self::key($subjects[3]), $states);
        self::assertSame(SubjectState::INACTIVE, $states[self::key($subjects[4])]);
        self::assertArrayNotHasKey(self::key($subjects[5]), $states);
        self::assertSame([], SubjectStates::of([]));
    }

    /**
     * The rows are given their subjects' states, unknown for one not read; a
     * resolved subject gives every row its own.
     *
     * @return void
     */
    public function testTheRowsAreGivenTheirSubjectsStates(): void
    {
        StubIdentity::query()->create(['id' => 'active']);

        $rows = [self::row(new Reference((new StubIdentity)->getMorphClass(), 'active')), self::row(new Reference('no model', 'x'))];

        self::assertSame([SubjectState::ACTIVE, SubjectState::UNKNOWN], \array_map(static fn (ReviewRow $row): SubjectState => $row->subjectState, SubjectStates::apply($rows)));

        $suspended = SuspendableIdentity::query()->create(['id' => 'suspended']);

        $suspended->suspended = true;

        self::assertSame(
            [SubjectState::INACTIVE, SubjectState::INACTIVE],
            \array_map(static fn (ReviewRow $row): SubjectState => $row->subjectState, SubjectStates::apply($rows, new Subject($suspended, $suspended))),
        );

        $active = StubIdentity::query()->findOrFail('active');

        self::assertSame(
            [SubjectState::ACTIVE],
            \array_map(static fn (ReviewRow $row): SubjectState => $row->subjectState, SubjectStates::apply([$rows[1]], new Subject($active, $active))),
        );
        self::assertSame([], SubjectStates::apply([]));
    }

    /**
     * A resolved subject whose principal is deleted softly, or whose separate
     * identity is, gives every row the inactive state, as a subject read by
     * reference does; one whose models are kept stays active.
     *
     * @return void
     */
    public function testASoftDeletedResolvedSubjectIsInactive(): void
    {
        $rows      = [self::row(new Reference('no model', 'x'))];
        $states    = static fn (Subject $subject): array => \array_map(static fn (ReviewRow $row): SubjectState => $row->subjectState, SubjectStates::apply($rows, $subject));
        $principal = NumberedIdentity::query()->create(['name' => 'departed']);
        $identity  = NumberedIdentity::query()->create(['name' => 'person']);
        $kept      = StubIdentity::query()->create(['id' => 'kept']);

        self::assertSame([SubjectState::ACTIVE], $states(new Subject($principal, $identity)));

        $principal->delete();

        self::assertSame([SubjectState::INACTIVE], $states(new Subject($principal, $principal)));
        self::assertSame([SubjectState::INACTIVE], $states(new Subject($principal, null)));

        $identity->delete();

        self::assertSame([SubjectState::INACTIVE], $states(new Subject($kept, $identity)));
        self::assertSame([SubjectState::ACTIVE], $states(new Subject($kept, $kept)));
        self::assertSame([SubjectState::ACTIVE], $states(new Subject(new Reference('no model', 'x'), null)));
    }

    /**
     * Return a row whose subject is the reference.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $subject
     * @return \SineMacula\Laravel\Authorization\Reviews\ReviewRow
     */
    private static function row(Reference $subject): ReviewRow
    {
        return new ReviewRow(
            'k',
            $subject,
            $subject,
            new Reference('role', 'r'),
            SourceKind::ROLE_GRANT,
            's',
            null,
            null,
            [],
            [],
            ['created_at' => null, 'updated_at' => null, 'expires_at' => null, 'route_expires_at' => null],
            null,
            GrantState::LIVE,
        );
    }

    /**
     * Return the key of a subject's reference.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $subject
     * @return string
     */
    private static function key(Reference $subject): string
    {
        return ReviewOrder::key([$subject->type, $subject->id]);
    }
}
