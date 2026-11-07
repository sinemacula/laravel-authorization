<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Contracts;

/**
 * Bulk resource attribute provider contract (AUTHZ-8.4, AUTHZ-10.3).
 *
 * An optional addition to `ResourceAttributeProvider` for a provider that can
 * read the attributes of many records at once. In a bulk check (`checkMany()`,
 * `canEach()` and `filterAuthorized()`), the first check on a record of the
 * provider's type that reads `resource` asks it for the records of that type
 * the chunk has still to decide in the scope that check is decided in, and asks
 * it in that scope, so a check over many resources never reads one record's
 * attributes at a time. A bulk check is decided in chunks of
 * `authorization.bulk.chunk_size`, and the records of each scope are read when
 * the first of them is needed, so the provider may be asked once per chunk and
 * scope, never about the whole batch at once; a provider that reads through the
 * tenant scope sees what it would see for each record on its own. A provider
 * that does not implement it is asked about each record on its own, when its
 * check reads `resource`, which keeps every decision exactly as it is, but
 * costs a read per resource when it reads the database.
 *
 * Each item is keyed by a token the package makes for it, and is the record's
 * reference with the model the check was given, exactly as `values()` is given
 * them; two models with the same key are two items, since each may hold other
 * attributes in memory. Each answer is what `values()` would return for the
 * item, or the exception it would throw: an item's failure fails that item's
 * check alone, and only if the check reads `resource`. A token left out of the
 * answer is asked on its own through `values()`, and so is every item when the
 * call itself throws. A value is used only by its own item's check, and never
 * by a check that does not read `resource`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface BulkResourceAttributeProvider extends ResourceAttributeProvider
{
    /**
     * Return the attribute values of each item, keyed by its token, as
     * `values()` returns them for the item, or the exception `values()` would
     * throw for it.
     *
     * @param  array<string, array{resource: \SineMacula\Laravel\Authorization\Support\ResourceReference, model: \Illuminate\Database\Eloquent\Model|null}>  $items
     * @return array<string, array<string, mixed>|\Throwable>
     *
     * @throws \Throwable
     */
    public function valuesMany(array $items): array;
}
