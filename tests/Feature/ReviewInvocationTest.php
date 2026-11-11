<?php

declare(strict_types = 1);

namespace Tests\Feature;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authorization\Console\Support\ReviewInvocation;
use SineMacula\Laravel\Authorization\Exceptions\UnresolvedSubjectException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Reviews\Enums\ReviewKind;
use SineMacula\Laravel\Authorization\Reviews\Enums\ScopeSelection;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Feature\Stubs\FixedConsoleSubjectResolver;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubTenant;
use Tests\TestCase;

/**
 * Feature tests for what one `authorization:review` invocation asks: its query
 * and reference, its scope, its window or actor, whether it lists direct grants
 * alone, and where its output goes, each read strictly and refused with a
 * message naming the argument or option, never a value.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(ReviewInvocation::class)]
final class ReviewInvocationTest extends TestCase
{
    /** @var string A key no definition has, which a holders query may still name. */
    private const string KEY = '01a1be88-d4d3-72cc-b9bc-620cc97d4906';

    /**
     * Return the invocations refused, each with the message it is refused with.
     *
     * @return iterable<string, array{array<string, mixed>, array<string, mixed>, string}>
     */
    public static function refusedInvocations(): iterable
    {
        $holders = ['query' => 'holders', 'reference' => 'role:' . self::KEY];

        yield 'an unknown query' => [['query' => 'everyone'], [], 'The query must be holders, holdings, expiring, granted_by or unused.'];
        yield 'no query' => [[], [], 'The query must be holders, holdings, expiring, granted_by or unused.'];
        yield 'holders with no reference' => [['query' => 'holders'], [], 'The holders and holdings queries name a reference as {type}:{key}.'];
        yield 'expiring with a reference' => [
            ['query' => 'expiring', 'reference' => 'role:1'],
            ['from' => 'now', 'until' => 'tomorrow'],
            'The expiring, granted_by and unused queries take no reference.',
        ];
        yield 'direct only for an actor' => [['query' => 'granted_by'], ['actor' => 'u:a', 'direct-only' => true], 'The --direct-only option is taken by the holders query alone.'];
        yield 'a window for holders' => [$holders, ['from' => 'now'], 'The --from option is taken by the expiring query alone.'];
        yield 'an actor for holders' => [$holders, ['actor' => 'u:a'], 'The --actor option is taken by the granted_by query alone.'];
        yield 'an action for holders' => [$holders, ['action' => 'audit:read'], 'The --action option is taken by the holdings query alone.'];
        yield 'an action for expiring' => [
            ['query' => 'expiring'],
            ['from' => 'now', 'until' => 'tomorrow', 'action' => 'audit:read'],
            'The --action option is taken by the holdings query alone.',
        ];
        yield 'expiring with no start' => [['query' => 'expiring'], ['until' => 'tomorrow'], 'The expiring query needs the --from option.'];
        yield 'expiring with no end' => [['query' => 'expiring'], ['from' => 'now'], 'The expiring query needs the --until option.'];
        yield 'an actor\'s grants with no actor' => [['query' => 'granted_by'], [], 'The granted_by query needs the --actor option.'];
        yield 'unused grants with no instant' => [['query' => 'unused'], [], 'The unused query needs the --since option.'];
        yield 'an instant for an actor' => [['query' => 'granted_by'], ['actor' => 'u:a', 'since' => '2026-01-01'], 'The --since option is taken by the unused query alone.'];
        yield 'unused grants with a reference' => [
            ['query' => 'unused', 'reference' => 'role:1'],
            ['since' => '2026-01-01'],
            'The expiring, granted_by and unused queries take no reference.',
        ];
        $several = 'Give at most one of the --tenant, --rooted-within and --everywhere options.';

        yield 'two scopes' => [$holders, ['tenant' => 'team:1', 'everywhere' => true], $several];
        yield 'a tenant and a root' => [$holders, ['tenant' => 'team:1', 'rooted-within' => 'team:1'], $several];
        yield 'a malformed tenant' => [$holders, ['tenant' => 'team'], 'The --tenant option must be in the format {morphType}:{key} (e.g. team:1).'];
        yield 'a malformed root' => [$holders, ['rooted-within' => ':1'], 'The --rooted-within option must be in the format {morphType}:{key} (e.g. team:1).'];
        yield 'an empty application' => [$holders, ['application' => ''], 'The --application option must be none, any or an application\'s name.'];
        yield 'an application no grant holds' => [$holders, ['application' => \str_repeat('a', 192)], 'The --application option must be none, any or an application\'s name.'];
        yield 'a non-string application' => [$holders, ['application' => true], 'The --application option must be none, any or an application\'s name.'];
    }

    /**
     * Each invocation that cannot be read is refused, naming the argument or
     * option and never a value.
     *
     * @param  array<string, mixed>  $arguments
     * @param  array<string, mixed>  $options
     * @param  string  $message
     * @return void
     */
    #[DataProvider('refusedInvocations')]
    public function testAnInvocationThatCannotBeReadIsRefused(array $arguments, array $options, string $message): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        ReviewInvocation::of($arguments, $options);
    }

    /**
     * The scope is what applies at the platform with no scope option, in none
     * of the applications by default; what applies in a tenant; the grants
     * rooted within one, in any application by default; or every grant; each in
     * the application selected, `none`, `any` or a name.
     *
     * @return void
     */
    public function testTheScopeOptionsNameTheScope(): void
    {
        $holders = ['query' => 'holders', 'reference' => 'role:' . self::KEY];
        $scope   = static fn (array $options): array => [
            ReviewInvocation::of($holders, $options)->scope->selection,
            ReviewInvocation::of($holders, $options)->scope->tenant?->id,
            ReviewInvocation::of($holders, $options)->scope->application->selection(),
            ReviewInvocation::of($holders, $options)->scope->application->application,
        ];

        self::assertSame([ScopeSelection::APPLIES_IN, null, 'none', null], $scope([]));
        self::assertSame([ScopeSelection::APPLIES_IN, '1', 'named', 'web'], $scope(['tenant' => 'team:1', 'application' => 'web']));
        self::assertSame([ScopeSelection::APPLIES_IN, null, 'any', null], $scope(['application' => 'any']));
        self::assertSame([ScopeSelection::ROOTED_WITHIN, '1', 'any', null], $scope(['rooted-within' => 'team:1']));
        self::assertSame([ScopeSelection::ROOTED_WITHIN, '1', 'none', null], $scope(['rooted-within' => 'team:1', 'application' => 'none']));
        self::assertSame([ScopeSelection::EVERYWHERE, null, 'any', null], $scope(['everywhere' => true]));
        self::assertSame([ScopeSelection::EVERYWHERE, null, 'named', 'none-of-these'], $scope(['everywhere' => true, 'everything' => null, 'application' => 'none-of-these']));
    }

    /**
     * A tenant naming a model's row is that row, by its morph class; one that
     * names no row is refused.
     *
     * @return void
     */
    public function testATenantModelIsResolvedToItsRow(): void
    {
        $tenant  = StubTenant::query()->create(['id' => 'tenant-1']);
        $holders = ['query' => 'holders', 'reference' => 'role:' . self::KEY];

        self::assertSame([$tenant->getMorphClass(), 'tenant-1'], [
            ReviewInvocation::of($holders, ['rooted-within' => StubTenant::class . ':tenant-1'])->scope->tenant?->type,
            ReviewInvocation::of($holders, ['rooted-within' => StubTenant::class . ':tenant-1'])->scope->tenant?->id,
        ]);

        $this->expectException(\InvalidArgumentException::class);

        ReviewInvocation::of($holders, ['tenant' => StubTenant::class . ':missing']);
    }

    /**
     * A holders reference names its role, permission or policy by the short
     * type or by the definition's morph type, and lists direct grants alone
     * when asked; a reference not in the format is refused.
     *
     * @return void
     */
    public function testAHoldersReferenceNamesItsDefinition(): void
    {
        $resolver = self::unused();

        foreach (['role' => new Role, 'permission' => new Permission, 'policy' => new Policy] as $type => $model) {
            $query = ReviewInvocation::of(['query' => 'holders', 'reference' => $type . ':' . self::KEY], ['direct-only' => $type === 'role'])->query($resolver);

            self::assertSame([$model->getMorphClass(), self::KEY, $type === 'role'], [$query->target?->type, $query->target?->id, $query->isDirectOnly]);
        }

        $morphed = ReviewInvocation::of(['query' => 'holders', 'reference' => (new Role)->getMorphClass() . ':' . self::KEY], ['direct-only' => false])->query($resolver);

        self::assertSame(ReviewKind::HOLDERS, $morphed->kind);
        self::assertSame((new Role)->getMorphClass(), $morphed->target?->type);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('The reference must be in the format {type}:{key} (e.g. role:1).');

        ReviewInvocation::of(['query' => 'holders', 'reference' => 'role'], [])->query($resolver);
    }

    /**
     * A holdings reference is resolved by the console subject resolver to its
     * principal and identity; a resolver that fails other than by refusing it
     * is reported as the reference being unresolvable, naming no failure, and
     * one that refuses it as its refusal says, naming the argument alone, never
     * the reference given.
     *
     * @return void
     */
    public function testAHoldingsReferenceIsResolvedByTheConsoleResolver(): void
    {
        $ann      = StubIdentity::query()->create(['id' => 'ann']);
        $resolver = new FixedConsoleSubjectResolver(new Subject($ann, $ann));
        $query    = ReviewInvocation::of(['query' => 'holdings', 'reference' => 'user:ann'], [])->query($resolver);

        self::assertSame([ReviewKind::HOLDINGS, $ann], [$query->kind, $query->subject?->subject]);
        self::assertSame(['user:ann'], $resolver->references);

        try {
            $failing = new FixedConsoleSubjectResolver(new Subject($ann, $ann), new \RuntimeException('secret'));

            ReviewInvocation::of(['query' => 'holdings', 'reference' => 'user:ann'], [])->query($failing);
            self::fail('A failing resolver resolved a subject.');
        } catch (UnresolvedSubjectException $exception) {
            self::assertSame('The reference could not be resolved.', $exception->getMessage());
            self::assertSame(UnresolvedSubjectException::UNRESOLVABLE, $exception->getCode());
        }

        // The resolver's own refusal is given by the argument's name alone.
        $refused = UnresolvedSubjectException::notFound('user:sentinel-value');

        try {
            ReviewInvocation::of(['query' => 'holdings', 'reference' => 'user:sentinel-value'], [])->query(new FixedConsoleSubjectResolver(new Subject($ann, $ann), $refused));
            self::fail('A refusing resolver resolved a subject.');
        } catch (UnresolvedSubjectException $exception) {
            self::assertSame(['The reference names no saved row.', $refused], [$exception->getMessage(), $exception->getPrevious()]);
        }
    }

    /**
     * A review of holdings keeps only the routes giving the action `--action`
     * names, and every route without it; an action that is no literal name, a
     * wildcard, a character no name holds or none at all, is refused by the
     * option alone, never the value given.
     *
     * @return void
     */
    public function testAnActionNarrowsTheHoldings(): void
    {
        $ann      = StubIdentity::query()->create(['id' => 'ann']);
        $resolver = new FixedConsoleSubjectResolver(new Subject($ann, $ann));
        $holdings = ['query' => 'holdings', 'reference' => 'user:ann'];

        self::assertSame('audit:read', ReviewInvocation::of($holdings, ['action' => 'audit:read'])->query($resolver)->action);
        self::assertNull(ReviewInvocation::of($holdings, [])->query($resolver)->action);
        self::assertNull(ReviewInvocation::of($holdings, ['action' => null])->query($resolver)->action);

        foreach (['audit:*', '*', 'sentinel value', '', true] as $action) {
            try {
                ReviewInvocation::of($holdings, ['action' => $action])->query($resolver);
                self::fail('An action that is no literal name was taken.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame('The --action option must be one action\'s name, with no wildcard (e.g. audit:read).', $exception->getMessage());
            }
        }
    }

    /**
     * An expiry window is read in UTC when it names no zone, and in its own
     * zone when it does; a window that is no date is refused, naming the
     * option.
     *
     * @return void
     */
    public function testAnExpiryWindowIsReadInUtc(): void
    {
        $resolver = self::unused();
        $query    = ReviewInvocation::of(['query' => 'expiring'], ['from' => '2026-12-01 00:00:00', 'until' => '2026-12-31T12:00:00+02:00'])->query($resolver);

        self::assertSame(['2026-12-01T00:00:00+00:00', '2026-12-31T10:00:00+00:00'], [$query->from?->toIso8601String(), $query->until?->toIso8601String()]);

        foreach ([['not a date', 'from'], ['', 'until'], [' ', 'until']] as [$value, $option]) {
            try {
                ReviewInvocation::of(['query' => 'expiring'], [...['from' => '2026-12-01', 'until' => '2026-12-02'], ...[$option => $value]])->query($resolver);
                self::fail('A window that is no date was read.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame("The --{$option} option must be a date and time (e.g. 2026-12-01T00:00:00Z).", $exception->getMessage());
            }
        }

        $this->expectExceptionMessage('An expiry window ends after it starts.');

        ReviewInvocation::of(['query' => 'expiring'], ['from' => '2026-12-02', 'until' => '2026-12-01'])->query($resolver);
    }

    /**
     * An unused review looks back to the instant `--since` names, read in UTC
     * when it names no zone; one that is no date is refused, naming the option.
     *
     * @return void
     */
    public function testAnUnusedReviewLooksBackToItsInstant(): void
    {
        $resolver = self::unused();
        $query    = ReviewInvocation::of(['query' => 'unused'], ['since' => '2026-12-01T02:00:00+02:00', 'everywhere' => true])->query($resolver);

        self::assertSame(ReviewKind::UNUSED, $query->kind);
        self::assertSame('2026-12-01T00:00:00+00:00', $query->since()?->toIso8601String());
        self::assertSame(ScopeSelection::EVERYWHERE, $query->scope->selection);

        $this->expectExceptionMessage('The --since option must be a date and time (e.g. 2026-12-01T00:00:00Z).');

        ReviewInvocation::of(['query' => 'unused'], ['since' => 'never'])->query($resolver);
    }

    /**
     * An actor is matched exactly as stored, its reference taken as given; one
     * not in the format is refused, naming the option.
     *
     * @return void
     */
    public function testAnActorIsTakenAsGiven(): void
    {
        $resolver = self::unused();
        $query    = ReviewInvocation::of(['query' => 'granted_by'], ['actor' => 'App\Models\User:a:b'])->query($resolver);

        self::assertEquals(new Reference('App\Models\User', 'a:b'), $query->actor);

        $this->expectExceptionMessage('The --actor option must be in the format {type}:{key} (e.g. role:1).');

        ReviewInvocation::of(['query' => 'granted_by'], ['actor' => 'user:'])->query($resolver);
    }

    /**
     * The output goes to the standard output unless a file is named, and an
     * existing file is overwritten only when forced.
     *
     * @return void
     */
    public function testTheOutputIsNamedAndForcedExplicitly(): void
    {
        $holders = ['query' => 'holders', 'reference' => 'role:' . self::KEY];

        self::assertSame([null, false], [ReviewInvocation::of($holders, [])->output, ReviewInvocation::of($holders, [])->isForced]);
        $forced = ReviewInvocation::of($holders, ['output' => 'out.jsonl', 'force' => true]);

        self::assertSame(['out.jsonl', true], [$forced->output, $forced->isForced]);
        self::assertSame('holders', ReviewInvocation::of($holders, [])->kind->value);
        self::assertSame('role:' . self::KEY, ReviewInvocation::of($holders, [])->reference);
    }

    /**
     * Return a console subject resolver for a query that resolves no subject.
     *
     * @return \Tests\Feature\Stubs\FixedConsoleSubjectResolver
     */
    private static function unused(): FixedConsoleSubjectResolver
    {
        $nobody = new Reference('u', 'nobody');

        return new FixedConsoleSubjectResolver(new Subject($nobody, $nobody));
    }
}
