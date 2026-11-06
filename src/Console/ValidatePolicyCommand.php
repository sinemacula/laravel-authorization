<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Console;

use Illuminate\Console\Command;
use SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException;
use SineMacula\Laravel\Authorization\Evaluation\PolicyValidator;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Support\PolicyDocument;

/**
 * Checks policy documents with the validator every write goes through
 * (AUTHZ-6.2, AUTHZ-6.10), so a document can be checked before it ships and a
 * stored one that no longer passes, after a limit was lowered or a permission
 * was removed, can be found.
 *
 * Each path is a JSON file holding one document or a JSON array of them, or a
 * directory whose `*.json` files are read. `--database` checks every stored
 * policy, platform-wide and tenant-owned alike, as stored, without hydrating
 * it; with no paths the database is checked. One line is printed for each
 * invalid document, `<source>: <name>: <reason>`, then a summary, and the
 * command fails when any document is invalid.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class ValidatePolicyCommand extends Command
{
    /** @var string The console command signature. */
    protected $signature = <<<'EOD'
        authorization:policy:validate
                                    {paths?* : JSON files of one document or an array of them, or directories of such files}
                                    {--database : Check every stored policy, as well as any paths}
        EOD;

    /** @var string The console command description. */
    protected $description = 'Check policy documents in files or the database against the policy validator';

    /** @var int How many documents were checked. */
    private int $checked = 0;

    /** @var int How many of the checked documents are invalid. */
    private int $invalid = 0;

    /**
     * Execute the console command.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\PolicyValidator  $validator
     * @return int
     */
    public function handle(PolicyValidator $validator): int
    {
        // The console resolves a command once, so a second call in the same
        // process starts its counts afresh.
        $this->checked = 0;
        $this->invalid = 0;

        /** @var list<string> $paths */
        $paths = $this->argument('paths');

        foreach ($paths as $path) {
            $this->checkPath($validator, $path);
        }

        if ($paths === [] || $this->option('database') === true) {
            $this->checkDatabase($validator);
        }

        $summary = "Checked {$this->checked} policy document(s): {$this->invalid} invalid.";

        if ($this->invalid > 0) {
            $this->error($summary);

            return self::FAILURE;
        }

        $this->info($summary);

        return self::SUCCESS;
    }

    /**
     * Check the documents of one path: every `*.json` file of a directory, or
     * the file itself.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\PolicyValidator  $validator
     * @param  string  $path
     * @return void
     */
    private function checkPath(PolicyValidator $validator, string $path): void
    {
        $found = \is_dir($path) ? \glob(\rtrim($path, '/') . '/*.json') : [$path];
        $files = $found === false ? [] : $found;

        foreach ($files as $file) {
            $this->checkFile($validator, $file);
        }
    }

    /**
     * Check the documents of one file: the document it holds, or each document
     * of the array it holds.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\PolicyValidator  $validator
     * @param  string  $file
     * @return void
     */
    private function checkFile(PolicyValidator $validator, string $file): void
    {
        $contents = \is_file($file) ? \file_get_contents($file) : false;
        $decoded  = \is_string($contents) ? \json_decode($contents, true) : null;

        if (!\is_array($decoded)) {
            $this->report($file, PolicyDocument::UNNAMED, [$contents === false ? 'The file cannot be read.' : 'The file does not hold a JSON object or array.']);

            return;
        }

        $isArray = \str_starts_with(\ltrim($contents), '[');

        foreach ($isArray ? $decoded : [$decoded] as $index => $document) {
            $this->check($validator, $isArray ? "{$file}[{$index}]" : $file, $document);
        }
    }

    /**
     * Check every stored policy, of every owner, as it is stored.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\PolicyValidator  $validator
     * @return void
     */
    private function checkDatabase(PolicyValidator $validator): void
    {
        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Policy> $class */
        $class = config('authorization.models.policy', Policy::class);

        /** @var \Illuminate\Support\LazyCollection<int, \SineMacula\Laravel\Authorization\Models\Policy> $policies */
        // @phpstan-ignore staticMethod.dynamicCall
        $policies = $class::query()->withoutGlobalScope(TenantScope::class)->orderBy('name')->cursor();

        foreach ($policies as $policy) {
            $this->checkStored($validator, $policy);
        }
    }

    /**
     * Check one stored policy's document, read from the column as stored and
     * named after the policy, as it is when read for evaluation.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\PolicyValidator  $validator
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @return void
     */
    private function checkStored(PolicyValidator $validator, Policy $policy): void
    {
        $name   = $policy->getAttribute('name');
        $source = "database:{$policy->id}";

        try {
            $document = PolicyDocument::decode($policy->getRawOriginal('document'), PolicyDocument::nameOf($name));
        } catch (InvalidPolicyDocumentException) {
            $this->report($source, PolicyDocument::nameOf($name), ['The stored document is not a JSON object.']);

            return;
        }

        $this->check($validator, $source, PolicyDocument::named($document, $name, true));
    }

    /**
     * Check one document and report it when it is invalid.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\PolicyValidator  $validator
     * @param  string  $source
     * @param  mixed  $document
     * @return void
     */
    private function check(PolicyValidator $validator, string $source, mixed $document): void
    {
        $name = PolicyDocument::nameOf(\is_array($document) ? ($document['name'] ?? null) : null);

        $this->report($source, $name, $validator->errors($document));
    }

    /**
     * Count one checked document, and print a line for it when there is any
     * reason it is invalid.
     *
     * @param  string  $source
     * @param  string  $name
     * @param  list<string>  $errors
     * @return void
     */
    private function report(string $source, string $name, array $errors): void
    {
        $this->checked++;

        if ($errors === []) {
            return;
        }

        $this->invalid++;
        $this->line("{$source}: {$name}: " . PolicyValidator::joined($errors));
    }
}
