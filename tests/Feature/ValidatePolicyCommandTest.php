<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Console\ValidatePolicyCommand;
use SineMacula\Laravel\Authorization\Contracts\ActionCatalogue;
use SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Support\DeclaredActionCatalogue;
use SineMacula\Laravel\Authorization\Support\PolicyDocument;
use Tests\Feature\Stubs\Enums\CataloguePermission;
use Tests\Feature\Stubs\StubTenant;
use Tests\TestCase;

/**
 * Feature tests for `authorization:policy:validate`, which checks policy
 * documents in files, directories or the database with the policy validator.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(ValidatePolicyCommand::class)]
final class ValidatePolicyCommandTest extends TestCase
{
    /** @var array<string, mixed> A valid document. */
    private const array VALID = ['name' => 'readers', 'statements' => [['effect' => 'allow', 'actions' => ['posts:create']]]];

    /** @var array<string, mixed> A document with an effect the language does not know. */
    private const array INVALID = ['name' => 'auditors', 'statements' => [['effect' => 'audit', 'actions' => ['posts:create']]]];

    /** @var string The directory the test's files are written to. */
    private string $directory = '';

    /**
     * Make a directory for the test's files.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->directory = \sys_get_temp_dir() . '/policy-validate-' . Str::random(12);

        \mkdir($this->directory);
    }

    /**
     * Remove the test's files and their directory, a subdirectory's files
     * before the subdirectory.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        foreach (\array_reverse(\glob($this->directory . '/{,*/}*', \GLOB_BRACE) ?: []) as $path) {
            \is_dir($path) ? \rmdir($path) : \unlink($path);
        }

        \rmdir($this->directory);

        parent::tearDown();
    }

    /**
     * A file holding a valid document passes.
     *
     * @return void
     */
    public function testAValidFilePasses(): void
    {
        $file = $this->write('readers.json', self::VALID);

        self::assertSame(0, Artisan::call('authorization:policy:validate', ['paths' => [$file]]));
        self::assertSame("Checked 1 policy document(s): 0 invalid.\n", Artisan::output());
    }

    /**
     * A file holding an invalid document fails, with a line naming the file,
     * the document and the reason.
     *
     * @return void
     */
    public function testAnInvalidFileFails(): void
    {
        $file = $this->write('auditors.json', self::INVALID);

        self::assertSame(1, Artisan::call('authorization:policy:validate', ['paths' => [$file]]));
        self::assertSame("{$file}: auditors: Invalid policy effect: 'audit'.\nChecked 1 policy document(s): 1 invalid.\n", Artisan::output());
    }

    /**
     * Each document of a file holding an array of them is checked, and an
     * invalid one is named by its place in the array.
     *
     * @return void
     */
    public function testChecksEachDocumentOfAnArrayFile(): void
    {
        $file = $this->write('all.json', [self::VALID, self::INVALID, ['statements' => []], 'readers']);

        self::assertSame(1, Artisan::call('authorization:policy:validate', ['paths' => [$file]]));
        self::assertSame(
            "{$file}[1]: auditors: Invalid policy effect: 'audit'.\n"
            . "{$file}[2]: [unnamed]: Policy document requires a non-empty name.\n"
            . "{$file}[3]: [unnamed]: Policy document must be a JSON object.\n"
            . "Checked 4 policy document(s): 3 invalid.\n",
            Artisan::output(),
        );
    }

    /**
     * An array file is read as an array of documents even when its JSON starts
     * with whitespace.
     *
     * @return void
     */
    public function testChecksEachDocumentOfAnArrayFileAfterLeadingWhitespace(): void
    {
        $file = $this->write('all.json', "\n  " . \json_encode([self::VALID, self::INVALID]));

        self::assertSame(1, Artisan::call('authorization:policy:validate', ['paths' => [$file]]));
        self::assertSame("{$file}[1]: auditors: Invalid policy effect: 'audit'.\nChecked 2 policy document(s): 1 invalid.\n", Artisan::output());
    }

    /**
     * An array file of valid documents passes, and an empty one holds none.
     *
     * @return void
     */
    public function testAnArrayFileOfValidDocumentsPasses(): void
    {
        $file  = $this->write('all.json', [self::VALID, self::VALID]);
        $empty = $this->write('none.json', []);

        self::assertSame(0, Artisan::call('authorization:policy:validate', ['paths' => [$file, $empty]]));
        self::assertSame("Checked 2 policy document(s): 0 invalid.\n", Artisan::output());
    }

    /**
     * A directory's `*.json` files are checked, in name order, and its other
     * files are not.
     *
     * @return void
     */
    public function testChecksTheJsonFilesOfADirectory(): void
    {
        $this->write('b.json', self::INVALID);
        $this->write('a.json', self::VALID);
        $this->write('notes.txt', 'not a policy');

        self::assertSame(1, Artisan::call('authorization:policy:validate', ['paths' => [$this->directory . '/']]));
        self::assertSame("{$this->directory}/b.json: auditors: Invalid policy effect: 'audit'.\nChecked 2 policy document(s): 1 invalid.\n", Artisan::output());
    }

    /**
     * A directory whose name holds glob metacharacters is listed as named, so
     * the invalid document in it is found rather than the directory passing as
     * one holding no documents.
     *
     * @return void
     */
    public function testChecksADirectoryWhoseNameHoldsGlobMetacharacters(): void
    {
        \mkdir($this->directory . '/policies[prod]');

        $this->write('policies[prod]/a.json', self::VALID);
        $this->write('policies[prod]/b.json', self::INVALID);

        $directory = $this->directory . '/policies[prod]';

        self::assertSame(1, Artisan::call('authorization:policy:validate', ['paths' => [$directory]]));
        self::assertSame("{$directory}/b.json: auditors: Invalid policy effect: 'audit'.\nChecked 2 policy document(s): 1 invalid.\n", Artisan::output());
    }

    /**
     * A file or directory that exists but cannot be read is reported as one
     * that cannot be read, and the command goes on to the paths after it and
     * the summary.
     *
     * @return void
     */
    public function testReportsAFileOrDirectoryThatCannotBeRead(): void
    {
        if (\function_exists('posix_geteuid') && \posix_geteuid() === 0) {
            self::markTestSkipped('The superuser can read a file of mode 000.');
        }

        $locked    = $this->write('locked.json', self::VALID);
        $directory = $this->directory . '/locked';
        $readable  = $this->write('readers.json', self::VALID);

        \mkdir($directory);
        \chmod($locked, 0);
        \chmod($directory, 0);

        try {
            self::assertSame(1, Artisan::call('authorization:policy:validate', ['paths' => [$locked, $directory, $readable]]));
            self::assertSame(
                "{$locked}: [unnamed]: The file cannot be read.\n"
                . "{$directory}: [unnamed]: The file cannot be read.\n"
                . "Checked 3 policy document(s): 2 invalid.\n",
                Artisan::output(),
            );
        } finally {
            \chmod($locked, 0o644);
            \chmod($directory, 0o755);
        }
    }

    /**
     * A path that is not a file, and a file that is not a JSON object or array,
     * each count as an invalid document.
     *
     * @return void
     */
    public function testRefusesAMissingOrNonJsonFile(): void
    {
        $missing = $this->directory . '/missing.json';
        $broken  = $this->write('broken.json', '{"name":');
        $scalar  = $this->write('scalar.json', '"readers"');

        self::assertSame(1, Artisan::call('authorization:policy:validate', ['paths' => [$missing, $broken, $scalar]]));
        self::assertSame(
            "{$missing}: [unnamed]: The file cannot be read.\n"
            . "{$broken}: [unnamed]: The file does not hold a JSON object or array.\n"
            . "{$scalar}: [unnamed]: The file does not hold a JSON object or array.\n"
            . "Checked 3 policy document(s): 3 invalid.\n",
            Artisan::output(),
        );
    }

    /**
     * Files are checked against the bound action catalogue, so with only the
     * package's own permissions declared a document naming another action is
     * refused.
     *
     * @return void
     */
    public function testChecksTheActionsAgainstTheCatalogue(): void
    {
        $file = $this->write('readers.json', self::VALID);

        $this->declare([]);

        self::assertSame(1, Artisan::call('authorization:policy:validate', ['paths' => [$file]]));
        self::assertStringContainsString("{$file}: readers: Policy statement #0 actions pattern 'posts:create' matches no declared permission.", Artisan::output());

        $this->declare([CataloguePermission::class]);

        self::assertSame(0, Artisan::call('authorization:policy:validate', ['paths' => [$file]]));
    }

    /**
     * With `--database`, a database of valid policies passes, platform-wide and
     * tenant-owned alike.
     *
     * @return void
     */
    public function testAValidDatabasePasses(): void
    {
        Policy::query()->create(['name' => 'readers', 'document' => self::VALID]);
        Policy::query()->create(['name' => 'writers', 'document' => self::VALID, 'tenant_type' => (new StubTenant)->getMorphClass(), 'tenant_id' => 'tenant-1']);

        self::assertSame(0, Artisan::call('authorization:policy:validate', ['--database' => true]));
        self::assertSame("Checked 2 policy document(s): 0 invalid.\n", Artisan::output());
    }

    /**
     * A stored policy over a limit fails, named by its key and its name, and a
     * tenant-owned one and a grantee's inline one are checked as well as the
     * platform's.
     *
     * @return void
     */
    public function testAStoredPolicyOverALimitFails(): void
    {
        $platform = Policy::query()->create(['name' => 'readers', 'document' => self::VALID]);
        $tenant   = Policy::query()->create(['name' => 'writers', 'document' => self::VALID, 'tenant_type' => (new StubTenant)->getMorphClass(), 'tenant_id' => 'tenant-1']);
        $inline   = Policy::query()->create(['name' => 'zeta', 'document' => self::VALID, 'owner_type' => 'user', 'owner_id' => '1']);

        $this->config()->set('authorization.policies.limits.pattern_length', 4);

        self::assertSame(1, Artisan::call('authorization:policy:validate', ['--database' => true]));
        self::assertSame(
            "database:{$platform->id}: readers: Policy statement #0 has 1 patterns or operands longer than the 4 characters allowed.\n"
            . "database:{$tenant->id}: writers: Policy statement #0 has 1 patterns or operands longer than the 4 characters allowed.\n"
            . "database:{$inline->id}: zeta: Policy statement #0 has 1 patterns or operands longer than the 4 characters allowed.\n"
            . "Checked 3 policy document(s): 3 invalid.\n",
            Artisan::output(),
        );
    }

    /**
     * Stored documents are read as stored, without hydration: one that is not a
     * JSON object is reported, and one is named after its policy.
     *
     * @return void
     */
    public function testReadsStoredDocumentsAsStored(): void
    {
        $broken = $this->insert('broken', 'null');
        $this->insert('unnamed', '{"statements":[{"effect":"allow","actions":["a"]}]}');
        $renamed = $this->insert('renamed', '{"name":"old","statements":[{"effect":"audit","actions":["a"]}]}');

        self::assertSame(1, Artisan::call('authorization:policy:validate'));
        self::assertSame(
            "database:{$broken}: broken: The stored document is not a JSON object.\n"
            . "database:{$renamed}: renamed: Invalid policy effect: 'audit'.\n"
            . "Checked 3 policy document(s): 2 invalid.\n",
            Artisan::output(),
        );
    }

    /**
     * A stored document whose own name is longer than its row's is measured
     * under the row's name by the command, as hydration measures it, so the two
     * agree whichever side of the byte limit it falls.
     *
     * @return void
     */
    public function testMeasuresAStoredDocumentUnderItsRowNameAsHydrationDoes(): void
    {
        // Named after its row `p`, the document is 73 bytes; as stored, under
        // its old name, it is 85.
        $id = $this->insert('p', (string) \json_encode(['name' => 'long-old-name', 'statements' => [['effect' => 'allow', 'actions' => ['posts:create']]]]));

        $this->config()->set('authorization.policies.limits.document_bytes', 80);

        self::assertSame(0, Artisan::call('authorization:policy:validate', ['--database' => true]));
        self::assertSame("Checked 1 policy document(s): 0 invalid.\n", Artisan::output());
        self::assertSame('p', PolicyDocument::hydrate(self::stored($id))->name);

        $this->config()->set('authorization.policies.limits.document_bytes', 72);

        self::assertSame(1, Artisan::call('authorization:policy:validate', ['--database' => true]));
        self::assertSame("database:{$id}: p: Policy document is 73 bytes, more than the 72 allowed.\nChecked 1 policy document(s): 1 invalid.\n", Artisan::output());

        try {
            PolicyDocument::hydrate(self::stored($id));

            self::fail('A stored document over the byte limit must not be hydrated.');
        } catch (InvalidPolicyDocumentException $exception) {
            self::assertSame('Invalid policy document \'p\': Policy document is 73 bytes, more than the 72 allowed.', $exception->getMessage());
        }
    }

    /**
     * Without paths the database is checked, an empty one passing; with paths
     * it is checked only when `--database` is given.
     *
     * @return void
     */
    public function testChecksTheDatabaseWithoutPathsOrWhenAsked(): void
    {
        self::assertSame(0, Artisan::call('authorization:policy:validate'));
        self::assertSame("Checked 0 policy document(s): 0 invalid.\n", Artisan::output());

        $broken = $this->insert('broken', 'null');

        $file = $this->write('readers.json', self::VALID);

        self::assertSame(0, Artisan::call('authorization:policy:validate', ['paths' => [$file]]));
        self::assertSame("Checked 1 policy document(s): 0 invalid.\n", Artisan::output());

        self::assertSame(1, Artisan::call('authorization:policy:validate', ['paths' => [$file], '--database' => true]));
        self::assertSame("database:{$broken}: broken: The stored document is not a JSON object.\nChecked 2 policy document(s): 1 invalid.\n", Artisan::output());
    }

    /**
     * Write a file of the test's directory, encoding a value that is not a
     * string as JSON.
     *
     * @param  string  $name
     * @param  mixed  $contents
     * @return string
     */
    private function write(string $name, mixed $contents): string
    {
        $path = $this->directory . '/' . $name;

        \file_put_contents($path, \is_string($contents) ? $contents : (string) \json_encode($contents));

        return $path;
    }

    /**
     * Store a policy row directly, bypassing the write-side validation, and
     * return its key.
     *
     * @param  string  $name
     * @param  string  $document
     * @return string
     */
    private function insert(string $name, string $document): string
    {
        $id = (string) Str::uuid();

        DB::table('policies')->insert(['id' => $id, 'name' => $name, 'document' => $document, 'created_at' => now(), 'updated_at' => now()]);

        return $id;
    }

    /**
     * Read a stored policy back by its key.
     *
     * @param  string  $id
     * @return \SineMacula\Laravel\Authorization\Models\Policy
     */
    private static function stored(string $id): Policy
    {
        return Policy::query()->whereKey($id)->firstOrFail();
    }

    /**
     * Declare the permission enums and check against the declared action
     * catalogue in place of the test suite's permissive one.
     *
     * @param  list<class-string>  $enums
     * @return void
     */
    private function declare(array $enums): void
    {
        $this->config()->set('authorization.permission_enums', $enums);

        $this->app?->instance(ActionCatalogue::class, $this->app->make(DeclaredActionCatalogue::class));
    }

    /**
     * Return the configuration repository.
     *
     * @return \Illuminate\Config\Repository
     */
    private function config(): ConfigRepository
    {
        /** @var \Illuminate\Config\Repository */
        return $this->app?->make(ConfigRepository::class);
    }
}
