<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Reviews;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Authorization\Support\GrantScope;

/**
 * One stored row a review row's route rests on: a grant, a role's permission
 * edge or a role's policy attachment, by its source key, with the scope it
 * holds in (none for a role edge, which holds wherever the role does) and its
 * expiry. A route lasts only while every row it rests on does.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class SupportingGrant
{
    /**
     * Create a new supporting grant.
     *
     * @param  string  $sourceKey
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope|null  $scope
     * @param  \Carbon\CarbonImmutable|null  $expiresAt
     */
    public function __construct(

        /** The key of the stored row (see `ReviewRow::$sourceKey`). */
        public string $sourceKey,

        /** Where the row holds; null for a role edge. */
        public ?GrantScope $scope,

        /** When the row expires, in UTC; null for never. */
        public ?CarbonImmutable $expiresAt,
    ) {}

    /**
     * Return the supporting grant as plain values, as a review row's versioned
     * shape holds it.
     *
     * @return array{source_key: string, scope: array{tenant: array{type: string, id: string}|null, application: string|null, include_subtree: bool}|null, expires_at: string|null}
     */
    public function toArray(): array
    {
        return [
            'source_key' => $this->sourceKey,
            'scope'      => ReviewRow::scopeArray($this->scope),
            'expires_at' => ReviewRow::instant($this->expiresAt),
        ];
    }
}
