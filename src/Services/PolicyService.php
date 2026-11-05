<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Services;

use Illuminate\Database\Eloquent\Collection;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Services\Support\RecordWriter;

/**
 * Creates, renames, describes, rewrites, deletes and lists policies.
 *
 * Every write runs in one transaction on the package's connection, through the
 * policy class `authorization.models.policy` configures, so the policy
 * observer, document validation and system protection apply. A policy that has
 * not been saved is refused with `UnsavedRecordException`, so a change never
 * creates one outside `create()`.
 *
 * Each method takes the acting subject as `$actor`, the reads as well as the
 * writes: null for console and system work.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @SuppressWarnings("php:S1172")
 */
final class PolicyService
{
    /**
     * Create a policy from its document, a JSON object or its decoded array.
     *
     * @param  string  $name
     * @param  array<array-key, mixed>|string  $document
     * @param  string|null  $description
     * @param  object|null  $actor
     * @return \SineMacula\Laravel\Authorization\Models\Policy
     *
     * @throws \Throwable
     */
    public function create(string $name, array|string $document, ?string $description = null, ?object $actor = null): Policy
    {
        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Policy> $class */
        $class = config('authorization.models.policy', Policy::class);

        return RecordWriter::save(static fn (): Policy => new $class, [
            'name'        => $name,
            'description' => $description,
            'document'    => $document,
        ]);
    }

    /**
     * Rename a policy.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @param  string  $name
     * @param  object|null  $actor
     * @return \SineMacula\Laravel\Authorization\Models\Policy
     *
     * @throws \Throwable
     */
    public function rename(Policy $policy, string $name, ?object $actor = null): Policy
    {
        return RecordWriter::save(static fn (): Policy => RecordWriter::existing('policy', $policy), ['name' => $name]);
    }

    /**
     * Set or clear a policy's description.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @param  string|null  $description
     * @param  object|null  $actor
     * @return \SineMacula\Laravel\Authorization\Models\Policy
     *
     * @throws \Throwable
     */
    public function describe(Policy $policy, ?string $description, ?object $actor = null): Policy
    {
        return RecordWriter::save(static fn (): Policy => RecordWriter::existing('policy', $policy), ['description' => $description]);
    }

    /**
     * Replace a policy's document.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @param  array<array-key, mixed>|string  $document
     * @param  object|null  $actor
     * @return \SineMacula\Laravel\Authorization\Models\Policy
     *
     * @throws \Throwable
     */
    public function rewrite(Policy $policy, array|string $document, ?object $actor = null): Policy
    {
        return RecordWriter::save(static fn (): Policy => RecordWriter::existing('policy', $policy), ['document' => $document]);
    }

    /**
     * Delete a policy, and with it every attachment of it.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @param  object|null  $actor
     * @return void
     *
     * @throws \Throwable
     */
    public function delete(Policy $policy, ?object $actor = null): void
    {
        RecordWriter::delete(static fn (): Policy => RecordWriter::existing('policy', $policy));
    }

    /**
     * List the policies, by name.
     *
     * @param  object|null  $actor
     * @return \Illuminate\Database\Eloquent\Collection<int, \SineMacula\Laravel\Authorization\Models\Policy>
     */
    public function list(?object $actor = null): Collection
    {
        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Policy> $class */
        $class = config('authorization.models.policy', Policy::class);

        return $class::query()->orderBy('name')->get();
    }
}
