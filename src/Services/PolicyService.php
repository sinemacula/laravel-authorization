<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Services;

use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Services\Support\RecordWriter;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Creates, renames, describes, rewrites, deletes and lists policies.
 *
 * Every write runs in one transaction on the package's connection, through the
 * policy class `authorization.models.policy` configures, so the policy
 * observer, document validation and system protection apply. A policy that has
 * not been saved is refused with `UnsavedRecordException`, so a change never
 * creates one outside `create()`.
 *
 * Each method takes the actor making the call as `$actor`, a model or a
 * reference, the reads as well as the writes: null for console and system work.
 * Every event a write dispatches carries it, with one operation id the call's
 * events share, once the write commits; it is never read from the authenticated
 * user.
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
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $actor
     * @return \SineMacula\Laravel\Authorization\Models\Policy
     *
     * @throws \Throwable
     */
    public function create(string $name, array|string $document, ?string $description = null, Model|Reference|null $actor = null): Policy
    {
        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Policy> $class */
        $class = config('authorization.models.policy', Policy::class);

        return RecordWriter::save($actor, static fn (): Policy => new $class, [
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
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $actor
     * @return \SineMacula\Laravel\Authorization\Models\Policy
     *
     * @throws \Throwable
     */
    public function rename(Policy $policy, string $name, Model|Reference|null $actor = null): Policy
    {
        return RecordWriter::save($actor, static fn (): Policy => RecordWriter::existing('policy', $policy), ['name' => $name]);
    }

    /**
     * Set or clear a policy's description.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @param  string|null  $description
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $actor
     * @return \SineMacula\Laravel\Authorization\Models\Policy
     *
     * @throws \Throwable
     */
    public function describe(Policy $policy, ?string $description, Model|Reference|null $actor = null): Policy
    {
        return RecordWriter::save($actor, static fn (): Policy => RecordWriter::existing('policy', $policy), ['description' => $description]);
    }

    /**
     * Replace a policy's document. The updated event reports the version and
     * digest of the document before and after, never the documents.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @param  array<array-key, mixed>|string  $document
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $actor
     * @return \SineMacula\Laravel\Authorization\Models\Policy
     *
     * @throws \Throwable
     */
    public function rewrite(Policy $policy, array|string $document, Model|Reference|null $actor = null): Policy
    {
        return RecordWriter::save($actor, static fn (): Policy => RecordWriter::existing('policy', $policy), ['document' => $document]);
    }

    /**
     * Delete a policy, and with it every attachment of it. The deleted event
     * lists every grantee it was attached to.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $actor
     * @return void
     *
     * @throws \Throwable
     */
    public function delete(Policy $policy, Model|Reference|null $actor = null): void
    {
        RecordWriter::delete($actor, static fn (): Policy => RecordWriter::existing('policy', $policy));
    }

    /**
     * List the policies, by name.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $actor
     * @return \Illuminate\Database\Eloquent\Collection<int, \SineMacula\Laravel\Authorization\Models\Policy>
     */
    public function list(Model|Reference|null $actor = null): Collection
    {
        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Policy> $class */
        $class = config('authorization.models.policy', Policy::class);

        return $class::query()->orderBy('name')->get();
    }
}
