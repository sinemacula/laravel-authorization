<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Contracts\Console\Kernel;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Console\ReviewCommand;
use SineMacula\Laravel\Authorization\Contracts\ConsoleSubjectResolver;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Reviews\ApplicationSelector;
use SineMacula\Laravel\Authorization\Reviews\ReviewQuery;
use SineMacula\Laravel\Authorization\Reviews\ReviewScope;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\Reference;
use Symfony\Component\Console\Input\ArgvInput;
use Symfony\Component\Console\Output\BufferedOutput;
use Symfony\Component\Console\Tester\CommandTester;
use Tests\Concerns\ReviewsAccess;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature tests for the `authorization:review` Artisan command (AUTHZ-11.6,
 * N97): an access review exported as JSON Lines on the trusted path, to the
 * standard output alone or to a file that exists only with `--force`, for every
 * query and scope option, a subject's holdings narrowed to an action among
 * them, exiting 0 when written, 2 for an invalid invocation and 1 when the
 * review fails, its errors on the standard error.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(ReviewCommand::class)]
final class ReviewCommandTest extends TestCase
{
    use ReviewsAccess;

    /** @var list<string> Files a test wrote, removed after it. */
    private array $files = [];

    /**
     * Remove the files the test wrote and unfreeze the clock.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        foreach ($this->files as $file) {
            if (!\is_file($file)) {
                continue;
            }

            \unlink($file);
        }

        Carbon::setTestNow();

        parent::tearDown();
    }

    /**
     * The command is registered under its `NAME` constant, the name its
     * signature declares.
     *
     * @return void
     */
    public function testTheCommandsNameIsItsConstant(): void
    {
        self::assertSame('authorization:review', ReviewCommand::NAME);
        self::assertInstanceOf(ReviewCommand::class, Artisan::all()[ReviewCommand::NAME] ?? null);
        self::assertSame(ReviewCommand::NAME, Artisan::all()[ReviewCommand::NAME]->getName());
    }

    /**
     * The holders of a role are exported to the standard output as JSON Lines
     * alone, the same lines the trusted export writes, and exit 0.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheHoldersAreExportedAsJsonLinesAlone(): void
    {
        Carbon::setTestNow('2026-11-08 12:00:00');

        $role = $this->holders();

        [$code, $output, $errors] = $this->review(['query' => 'holders', 'reference' => 'role:' . Reference::of($role)->id, '--everywhere' => true]);

        self::assertSame(0, $code);
        self::assertSame('', $errors);
        self::assertSame(self::exported(ReviewQuery::holders($role, ReviewScope::everywhere())), $output);
        self::assertStringNotContainsString("\e", $output);
        self::assertSame(['header', 'row', 'row', 'row', 'footer'], \array_column(self::lines($output), 'record'));
    }

    /**
     * Every query and scope option reads the review it names: the direct
     * holders, a saved subject's holdings, what expires in a window, an actor's
     * grants and the grants unused since an instant, applying in a tenant or
     * the platform, rooted within a tenant or everywhere, in the application
     * selected.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEveryQueryAndScopeOptionIsRead(): void
    {
        Carbon::setTestNow('2026-11-08 12:00:00');

        $this->tree();

        $role  = self::role('reviewed');
        $child = self::role('child', $role);
        $ann   = StubIdentity::query()->create(['id' => 'ann']);
        $soon  = now()->addWeek();

        self::grants()->grantRole($ann, $role, $soon, tenant: self::tenant('acct1'), application: 'web');
        self::grants()->grantRole(new Reference('u', 'inherits'), $child);

        DB::table('authorizable_roles')->update(['granted_by_type' => 'user', 'granted_by_id' => 'writer']);

        $target = 'role:' . Reference::of($role)->id;
        $until  = $soon->copy()->addDay();

        $cases = [
            [
                ['query' => 'holders', 'reference' => $target, '--direct-only' => true, '--everywhere' => true],
                ReviewQuery::holders($role, ReviewScope::everywhere(), true),
            ],
            [
                ['query' => 'holders', 'reference' => $target, '--tenant' => 'tenant:acct1', '--application' => 'web'],
                ReviewQuery::holders($role, ReviewScope::appliesIn(self::tenant('acct1'), ApplicationSelector::named('web'))),
            ],
            [
                ['query' => 'holders', 'reference' => $target],
                ReviewQuery::holders($role, ReviewScope::appliesIn(null, ApplicationSelector::none())),
            ],
            [
                ['query' => 'holdings', 'reference' => StubIdentity::class . ':ann', '--rooted-within' => 'tenant:org1'],
                ReviewQuery::holdings(self::subjectOf($ann), ReviewScope::rootedWithin(self::tenant('org1'))),
            ],
            [
                ['query' => 'expiring', '--from' => now()->toIso8601String(), '--until' => $until->toIso8601String(), '--everywhere' => true, '--application' => 'none'],
                ReviewQuery::expiring(ReviewScope::everywhere(ApplicationSelector::none()), now(), $until),
            ],
            [
                ['query' => 'granted_by', '--actor' => 'user:writer', '--everywhere' => true, '--application' => 'any'],
                ReviewQuery::grantedBy(new Reference('user', 'writer'), ReviewScope::everywhere()),
            ],
            [
                ['query' => 'unused', '--since' => now()->subDay()->toIso8601String(), '--everywhere' => true],
                ReviewQuery::unused(ReviewScope::everywhere(), now()->subDay()),
            ],
        ];

        foreach ($cases as $index => [$parameters, $query]) {
            [$code, $output, $errors] = $this->review($parameters);

            self::assertSame([0, ''], [$code, $errors], "case {$index}");
            self::assertSame(self::exported($query), $output, "case {$index}");
        }

        self::assertCount(2, \array_filter(self::lines($this->review($cases[0][0])[1]), static fn (array $line): bool => $line['record'] !== 'row'));
        self::assertNotSame(self::exported($cases[0][1]), self::exported(ReviewQuery::holders($role, ReviewScope::everywhere())));
    }

    /**
     * A saved subject's holdings narrowed by `--action` are exported as the
     * trusted export of the review filtered by the action writes them: its
     * header names the action and says the rows cover the stored grants alone,
     * and only the routes giving the action are rows, each with its evidence.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheHoldingsOfAnActionAreExported(): void
    {
        Carbon::setTestNow('2026-11-08 12:00:00');

        $ann  = StubIdentity::query()->create(['id' => 'ann']);
        $role = self::role('auditor');

        self::grants()->grantPermission($ann, self::permission('audit:read'));
        self::grants()->grantPermission($ann, self::permission('posts:read'));
        self::grants()->grantRole($ann, $role);
        $role->givePermissionTo(self::permission('audit:*'));

        $parameters = ['query' => 'holdings', 'reference' => StubIdentity::class . ':ann', '--everywhere' => true];
        $query      = ReviewQuery::holdings(self::subjectOf($ann), ReviewScope::everywhere());

        [$code, $output, $errors] = $this->review([...$parameters, '--action' => 'audit:read']);

        self::assertSame([0, ''], [$code, $errors]);
        self::assertSame(self::exported($query->forAction('audit:read')), $output);

        $lines = self::lines($output);

        self::assertSame(['audit:read', true], [$lines[0]['action'] ?? null, $lines[0]['stored_inventory_only'] ?? null]);
        self::assertSame(['header', 'row', 'row', 'footer'], \array_column($lines, 'record'));
        self::assertSame(['audit:read', 'audit:read'], \array_column(\array_column(\array_slice($lines, 1, 2), 'action_evidence'), 'action'));

        [, $unfiltered] = $this->review($parameters);

        self::assertSame(self::exported($query), $unfiltered);
        self::assertArrayNotHasKey('action', self::lines($unfiltered)[0]);
        self::assertCount(6, self::lines($unfiltered));
    }

    /**
     * The export is written to the file named, the standard output left empty;
     * a file that exists is refused unless `--force` is given, and then
     * overwritten; and a file that cannot be opened is refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheOutputFileIsWrittenOnlyWhenNewOrForced(): void
    {
        $role = $this->holders();
        $file = $this->file();
        $base = ['query' => 'holders', 'reference' => 'role:' . Reference::of($role)->id, '--everywhere' => true];

        [$code, $output] = $this->review([...$base, '--output' => $file]);

        self::assertSame([0, ''], [$code, $output]);
        self::assertSame(['header', 'row', 'row', 'row', 'footer'], \array_column(self::lines((string) \file_get_contents($file)), 'record'));
        $open = \array_filter(\get_resources('stream'), static fn ($stream): bool => (\stream_get_meta_data($stream)['uri'] ?? null) === $file);

        self::assertSame([], $open, 'The file was left open.');

        \file_put_contents($file, 'kept');

        [$code, $output, $errors] = $this->review([...$base, '--output' => $file]);

        self::assertSame([2, ''], [$code, $output]);
        self::assertSame("The --output file exists; give --force to overwrite it.\n", $errors);
        self::assertSame('kept', \file_get_contents($file));

        [$code] = $this->review([...$base, '--output' => $file, '--force' => true]);

        self::assertSame(0, $code);
        self::assertStringStartsWith('{"record":"header"', (string) \file_get_contents($file));

        [$code, , $errors] = $this->review([...$base, '--output' => \sys_get_temp_dir() . '/missing-' . \bin2hex(\random_bytes(4)) . '/out.jsonl']);

        self::assertSame([2, "The --output file could not be opened.\n"], [$code, $errors]);
    }

    /**
     * Each invalid invocation exits 2, its error on the standard error alone,
     * naming no value given: an unknown option, a missing query, an unknown
     * query, an option given without its value, an option the query does not
     * take, two scopes, a target that is no definition, and a subject or tenant
     * that is malformed, of no model or not saved, named by its argument or
     * option alone.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnInvalidInvocationExitsTwo(): void
    {
        StubIdentity::query()->create(['id' => 'ann']);

        $refusals = [
            [['query' => 'holders', '--secret' => 'sentinel-value'], 'The "--secret" option does not exist.'],
            [[], 'Not enough arguments (missing: "query").'],
            [['query' => 'sentinel-value'], 'The query must be holders, holdings, expiring, granted_by or unused.'],
            [['query' => 'holders', 'reference' => 'role:x', '--from' => 'sentinel-value'], 'The --from option is taken by the expiring query alone.'],
            [
                ['query' => 'holders', 'reference' => 'role:x', '--everywhere' => true, '--tenant' => 'team:sentinel-value'],
                'Give at most one of the --tenant, --rooted-within and --everywhere options.',
            ],
            [
                ['query' => 'holders', 'reference' => 'sentinel:value'],
                'An access review lists the holders of a role, a permission or a policy, named by its model or a reference to it.',
            ],
            [['query' => 'holdings', 'reference' => 'sentinel-value'], 'The reference must be in the format {morphType}:{key} (e.g. user:1).'],
            [['query' => 'holdings', 'reference' => 'sentinel-value:1'], 'The reference\'s type is not an Eloquent model.'],
            [['query' => 'holdings', 'reference' => StubIdentity::class . ':sentinel-value'], 'The reference names no saved row.'],
            [['query' => 'holders', 'reference' => 'role:x', '--tenant' => StubIdentity::class . ':sentinel-value'], 'The --tenant option names no saved row.'],
            [['query' => 'holders', 'reference' => 'role:x', '--rooted-within' => StubIdentity::class . ':sentinel-value'], 'The --rooted-within option names no saved row.'],
            [['query' => 'holders', 'reference' => 'role:x', '--action' => 'sentinel-value'], 'The --action option is taken by the holdings query alone.'],
            [
                ['query' => 'holdings', 'reference' => StubIdentity::class . ':ann', '--action' => 'sentinel-value:*'],
                'The --action option must be one action\'s name, with no wildcard (e.g. audit:read).',
            ],
        ];

        foreach ($refusals as [$parameters, $message]) {
            [$code, $output, $errors] = $this->review($parameters);

            self::assertSame([2, '', $message . "\n"], [$code, $output, $errors]);
            self::assertStringNotContainsString('sentinel-value', $errors);
        }

        $kernel = $this->app?->make(Kernel::class);

        self::assertInstanceOf(Kernel::class, $kernel);

        $line = new ArgvInput(['artisan', 'authorization:review', 'holders', 'role:x', '--tenant']);
        $out  = new BufferedOutput;

        self::assertSame(2, $kernel->handle($line, $out));
        self::assertStringContainsString('The --tenant option must be given a value.', $out->fetch());

        $out = new BufferedOutput;

        self::assertSame(2, $kernel->handle(new ArgvInput(['artisan', 'authorization:review', 'holdings', StubIdentity::class . ':ann', '--action']), $out));
        self::assertStringContainsString('The --action option must be given a value.', $out->fetch());

        foreach ([['holders', 'role:x'], ['unused', '--everywhere']] as $arguments) {
            $out = new BufferedOutput;

            self::assertSame(2, $kernel->handle(new ArgvInput(['artisan', 'authorization:review', ...$arguments, '--since']), $out));
            self::assertStringContainsString('The --since option must be given a value.', $out->fetch());
        }
    }

    /**
     * A review that fails exits 1, naming the class of what it threw and no
     * value, and writes nothing to the standard output when it fails before its
     * first page.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAReviewThatFailsExitsOne(): void
    {
        $parent = self::role('parent');
        $child  = self::role('child', $parent);

        self::grants()->grantRole(new Reference('u', 'a'), $child);

        DB::table('roles')->where('id', $parent->getKey())->update(['parent_id' => $child->getKey()]);

        [$code, $output, $errors] = $this->review(['query' => 'holders', 'reference' => 'role:' . Reference::of($parent)->id, '--everywhere' => true]);

        self::assertSame([1, ''], [$code, $output]);
        self::assertSame("The review could not be exported (SineMacula\\Laravel\\Authorization\\Exceptions\\RoleHierarchyCycleException).\n", $errors);
    }

    /**
     * Return a new role held by three grantees.
     *
     * @return \SineMacula\Laravel\Authorization\Models\Role
     *
     * @throws \Throwable
     */
    private function holders(): Role
    {
        $role = self::role('reviewed');

        foreach (['a', 'b', 'c'] as $id) {
            self::grants()->grantRole(new Reference('u', $id), $role);
        }

        return $role;
    }

    /**
     * Run the command, returning its exit code, its standard output and its
     * standard error.
     *
     * @param  array<string, mixed>  $parameters
     * @return array{int, string, string}
     */
    private function review(array $parameters): array
    {
        $kernel = $this->app?->make(Kernel::class);

        self::assertInstanceOf(Kernel::class, $kernel);

        $tester = new CommandTester($kernel->all()['authorization:review']);
        $code   = $tester->execute($parameters, ['capture_stderr_separately' => true]);

        return [$code, $tester->getDisplay(), $tester->getErrorOutput()];
    }

    /**
     * Return the JSON Lines the trusted export of the query writes.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\ReviewQuery  $query
     * @return string
     *
     * @throws \Throwable
     */
    private static function exported(ReviewQuery $query): string
    {
        $written = '';

        self::reviews()->trustedExport($query, static function (string $line) use (&$written): void {
            $written .= $line;
        });

        return $written;
    }

    /**
     * Return each line of the JSON Lines decoded.
     *
     * @param  string  $output
     * @return list<array<string, mixed>>
     *
     * @throws \JsonException
     */
    private static function lines(string $output): array
    {
        $lines = [];

        foreach (\explode("\n", \rtrim($output, "\n")) as $line) {
            /** @var array<string, mixed> $decoded */
            $decoded = \json_decode($line, true, 512, \JSON_THROW_ON_ERROR);
            $lines[] = $decoded;
        }

        return $lines;
    }

    /**
     * Return the subject the console resolves the identity to.
     *
     * @param  \Tests\Feature\Stubs\StubIdentity  $identity
     * @return \SineMacula\Laravel\Authorization\Subject
     */
    private static function subjectOf(StubIdentity $identity): Subject
    {
        /** @var \SineMacula\Laravel\Authorization\Contracts\ConsoleSubjectResolver $resolver */
        $resolver = app(ConsoleSubjectResolver::class);

        return $resolver->resolve(StubIdentity::class . ':' . Reference::of($identity)->id);
    }

    /**
     * Return the path of a file that does not exist yet, removed after the
     * test.
     *
     * @return string
     *
     * @throws \Random\RandomException
     */
    private function file(): string
    {
        $file = \sys_get_temp_dir() . '/review-' . \bin2hex(\random_bytes(6)) . '.jsonl';

        $this->files[] = $file;

        return $file;
    }
}
