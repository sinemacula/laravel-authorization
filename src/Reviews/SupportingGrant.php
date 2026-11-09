<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Reviews;

use Carbon\CarbonImmutable;

/**
 * One stored row a review row's route rests on: a grant, a role's permission
 * edge or a role's policy attachment, by its source key, with the scope it
 * holds in, as stored (see `OriginScope`; none for a role edge, which holds
 * wherever the role does), and its expiry. A route lasts only while every row
 * it rests on does.
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
     * @param  \SineMacula\Laravel\Authorization\Reviews\OriginScope|null  $scope
     * @param  \Carbon\CarbonImmutable|null  $expiresAt
     */
    public function __construct(

        /** The key of the stored row (see `ReviewRow::$sourceKey`). */
        public string $sourceKey,

        /** Where the row holds, as stored; null for a role edge. */
        public ?OriginScope $scope,

        /** When the row expires, in UTC; null for never. */
        public ?CarbonImmutable $expiresAt,
    ) {}

    /**
     * Return the supporting grant as plain values, as a review row's versioned
     * shape holds it.
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @formatter:off
     *
     * @return array{source_key: string, scope: array{tenant: array{type: string|null, id: string|null}|null, application: string|null, include_subtree: bool}|null, expires_at: string|null}
     *
     * @formatter:on
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     */
    public function toArray(): array
    {
        return [
            'source_key' => $this->sourceKey,
            'scope'      => $this->scope?->toArray(),
            'expires_at' => ReviewRow::instant($this->expiresAt),
        ];
    }
}
