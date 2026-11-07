<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Services;

use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Administration\ActingContext;
use SineMacula\Laravel\Authorization\Concerns\HasContainerInstance;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableTenant;
use SineMacula\Laravel\Authorization\Exceptions\InvalidGranteeException;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Services\Support\RecordWriter;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Creates, renames, describes, rewrites, deletes and lists policies.
 *
 * Every write runs in one transaction on the package's connection, through the
 * policy class `authorization.models.policy` configures, so the policy
 * observer, document validation and system protection apply. A policy that has
 * not been saved is refused with `UnsavedRecordException`, so a change never
 * creates one outside `create()` or `createInline()`.
 *
 * A policy `create()` makes is managed: attached to any number of grantees and
 * roles. One `createInline()` makes belongs to one grantee, is attached to that
 * grantee alone, and is deleted with it (AUTHZ-6.9); its name is unique among
 * that grantee's inline policies. Both validate the document the same way.
 *
 * Each method takes the acting context making the call as `$actor`, the reads
 * as well as the writes: null for trusted system work, such as seeders,
 * migrations and console commands (N75). A write with an acting context is
 * delegated administration (AUTHZ-11.1): it is decided as the actor, through
 * `check()`, on the definition's operation resource, under
 * `authorization:policy.create` (an inline policy included), `.rename`,
 * `.update` (a rewrite or a description) or `.delete`, inside its transaction
 * before anything is written, and refused with the decision's
 * `AuthorizationException` when it is not allowed. A change is made only from
 * the tenant that owns the policy, a platform policy's from the platform
 * (`administration.owner`, D20): `create()` makes one owned by the tenant it is
 * given, else by the platform, so a tenant's administrator creates its tenant's
 * policies from that tenant's context. A delegated change weighs, and writes,
 * the policy as stored, discarding changes to the model in hand that were not
 * saved, and a rewrite is decided on the operation resource
 * `OperationResource::rewrite()` builds, as a screen builds it. Creating,
 * renaming and describing a policy widen no one, and deleting one does unless
 * it denies. A rewrite that only removes allows or adds denies narrows; one
 * that lifts a deny is refused as `administration.unprovable`; one that adds
 * allows is weighed against every holder of the policy and needs the policy
 * route for what it adds, and, for a policy in use as a boundary,
 * `authorization:administration.unbounded` (see `PolicyRewrite`). A read is not
 * decided yet. Every event a write dispatches carries the operation, with the
 * actor, its mode and the action, once the write commits; the actor is never
 * read from the authenticated user.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @SuppressWarnings("php:S1172")
 */
final class PolicyService
{
    use HasContainerInstance;

    /**
     * Create a policy from its document, a JSON object or its decoded array,
     * owned by the tenant given, or by the platform for none.
     *
     * @param  string  $name
     * @param  array<array-key, mixed>|string  $document
     * @param  string|null  $description
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext|null  $actor
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Contracts\AuthorizableTenant|null  $tenant
     * @return \SineMacula\Laravel\Authorization\Models\Policy
     *
     * @throws \Throwable
     */
    public function create(string $name, array|string $document, ?string $description = null, ?ActingContext $actor = null, AuthorizableTenant|Model|null $tenant = null): Policy
    {
        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Policy> $class */
        $class = config('authorization.models.policy', Policy::class);

        return RecordWriter::save($actor, PackagePermissions::POLICY_CREATE, static fn (): Policy => RecordWriter::ownedBy(new $class, $tenant), [
            'name'        => $name,
            'description' => $description,
            'document'    => $document,
        ]);
    }

    /**
     * Create an inline policy for the grantee from its document, a JSON object
     * or its decoded array, validated as any policy's is. The policy belongs to
     * the grantee: it is attached to that grantee alone, and is deleted with
     * it. Creating it does not attach it; attach it to the grantee, in the
     * scope it holds in, as any policy.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference  $owner
     * @param  string  $name
     * @param  array<array-key, mixed>|string  $document
     * @param  string|null  $description
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext|null  $actor
     * @return \SineMacula\Laravel\Authorization\Models\Policy
     *
     * @throws \Throwable
     */
    public function createInline(Model|Reference $owner, string $name, array|string $document, ?string $description = null, ?ActingContext $actor = null): Policy
    {
        $reference = self::owner($owner);

        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Policy> $class */
        $class = config('authorization.models.policy', Policy::class);

        return RecordWriter::save($actor, PackagePermissions::POLICY_CREATE, static fn (): Policy => new $class, [
            'name'        => $name,
            'description' => $description,
            'owner_type'  => $reference->type,
            'owner_id'    => $reference->id,
            'document'    => $document,
        ]);
    }

    /**
     * Rename a policy.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @param  string  $name
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext|null  $actor
     * @return \SineMacula\Laravel\Authorization\Models\Policy
     *
     * @throws \Throwable
     */
    public function rename(Policy $policy, string $name, ?ActingContext $actor = null): Policy
    {
        return RecordWriter::save($actor, PackagePermissions::POLICY_RENAME, static fn (): Policy => RecordWriter::existing('policy', $policy), ['name' => $name]);
    }

    /**
     * Set or clear a policy's description.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @param  string|null  $description
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext|null  $actor
     * @return \SineMacula\Laravel\Authorization\Models\Policy
     *
     * @throws \Throwable
     */
    public function describe(Policy $policy, ?string $description, ?ActingContext $actor = null): Policy
    {
        return RecordWriter::save($actor, PackagePermissions::POLICY_UPDATE, static fn (): Policy => RecordWriter::existing('policy', $policy), ['description' => $description]);
    }

    /**
     * Replace a policy's document. The updated event reports the version and
     * digest of the document before and after, never the documents.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @param  array<array-key, mixed>|string  $document
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext|null  $actor
     * @return \SineMacula\Laravel\Authorization\Models\Policy
     *
     * @throws \Throwable
     */
    public function rewrite(Policy $policy, array|string $document, ?ActingContext $actor = null): Policy
    {
        return RecordWriter::save($actor, PackagePermissions::POLICY_UPDATE, static fn (): Policy => RecordWriter::existing('policy', $policy), ['document' => $document]);
    }

    /**
     * Delete a policy, and with it every attachment of it. The deleted event
     * lists every grantee it was attached to.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext|null  $actor
     * @return void
     *
     * @throws \Throwable
     */
    public function delete(Policy $policy, ?ActingContext $actor = null): void
    {
        RecordWriter::delete($actor, PackagePermissions::POLICY_DELETE, static fn (): Policy => RecordWriter::existing('policy', $policy));
    }

    /**
     * List the policies, by name.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext|null  $actor
     * @return \Illuminate\Database\Eloquent\Collection<int, \SineMacula\Laravel\Authorization\Models\Policy>
     */
    public function list(?ActingContext $actor = null): Collection
    {
        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Policy> $class */
        $class = config('authorization.models.policy', Policy::class);

        return $class::query()->orderBy('name')->get();
    }

    /**
     * Return the reference to the grantee an inline policy is created for, once
     * it is known to be one a grant can be written for: a saved model with a
     * key, or a reference with a type and a key.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference  $owner
     * @return \SineMacula\Laravel\Authorization\Support\Reference
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidGranteeException
     */
    private static function owner(Model|Reference $owner): Reference
    {
        $reference = Reference::of($owner);

        if ($reference->type === '' || $reference->id === '' || ($owner instanceof Model && !$owner->exists)) {
            throw new InvalidGranteeException($owner);
        }

        return $reference;
    }
}
