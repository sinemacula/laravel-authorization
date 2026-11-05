<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Support;

use SineMacula\Laravel\Authorization\Evaluation\Policy;

/**
 * A policy document as the policy events report it: its schema version and a
 * digest of its content, never the document itself.
 *
 * The digest is the SHA-256 of the document's canonical JSON: every object's
 * keys sorted, lists kept in order, slashes and Unicode left unescaped. Two
 * documents with the same content have the same digest whatever order their
 * keys were written in, so a listener can tell whether a document changed, and
 * match it against a copy it holds, without the events carrying the statements.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class DocumentDigest
{
    /**
     * Create a new document digest.
     *
     * @param  int  $version
     * @param  string  $digest
     */
    public function __construct(

        /** The document's schema version. */
        public int $version,

        /** The SHA-256 of the document's canonical JSON, in lowercase hex. */
        public string $digest,
    ) {}

    /**
     * Return the digest of a decoded policy document. A document that names no
     * version is the current version.
     *
     * @param  array<array-key, mixed>  $document
     * @return self
     *
     * @throws \JsonException
     */
    public static function of(array $document): self
    {
        $version = $document['version'] ?? Policy::CURRENT_VERSION;

        return new self(
            \is_int($version) ? $version : Policy::CURRENT_VERSION,
            \hash('sha256', \json_encode(self::canonical($document), JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION)),
        );
    }

    /**
     * Return the value with every object's keys sorted, at every depth, and
     * every list in its order.
     *
     * @param  mixed  $value
     * @return mixed
     */
    private static function canonical(mixed $value): mixed
    {
        if (!\is_array($value)) {
            return $value;
        }

        $value = \array_map(self::canonical(...), $value);

        if (!\array_is_list($value)) {
            \ksort($value, SORT_STRING);
        }

        return $value;
    }
}
