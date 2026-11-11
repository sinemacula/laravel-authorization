<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Reviews\Support;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Encryption\MissingAppKeyException;
use SineMacula\Laravel\Authorization\Administration\ActingContext;
use SineMacula\Laravel\Authorization\Exceptions\InvalidReviewCursorException;
use SineMacula\Laravel\Authorization\Reviews\ReviewQuery;
use SineMacula\Laravel\Authorization\Reviews\ReviewRow;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * The cursors of a paged access review: opaque, tamper-evident tokens that
 * carry a review's position (see `ReviewPosition`) from one page to the next.
 *
 * A cursor is its payload and its signature, each base64url-encoded, unpadded,
 * and joined by a dot. The payload holds the row schema version, the review's
 * instant and the sort key of the last row returned, whose parts are the
 * references and scope values that row already shows, so a cursor discloses
 * nothing a page did not. The signature is an HMAC-SHA256, keyed from the
 * application key, of the payload, the schema version included, and of what the
 * cursor is bound to: the query (its kind, target or subject, scope selection,
 * tenant, application selector, window, actor, whether it lists direct grants
 * alone, and the action a review of holdings is filtered by) and the reviewer
 * (its principal and any impersonator) or the trusted path.
 *
 * A sort key holds a fixed number of parts however deep the role hierarchy runs
 * (see `RowCollector`), each a morph type, a key, a scope value or a stored
 * row's key, which the grant tables bound to 191 characters a column, so a
 * cursor stays a few kilobytes, well under the longest one read (`MAX_LENGTH`).
 *
 * A cursor is read only once its signature is verified, in constant time, for
 * the query and reviewer it is presented with, and only in the one text that
 * encodes it: each part must be exactly the canonical base64url of its bytes,
 * so no other text, with padding, a line break, another alphabet or other spare
 * bits, reads as the same cursor. A cursor changed in any byte, issued for
 * another query, another reviewer or the trusted path, of another schema
 * version, or that is not a cursor at all is refused with the one
 * `InvalidReviewCursorException`, which says nothing of why.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ReviewCursor
{
    /** @var string What the signing key is derived for, so the application key signs nothing else this way. */
    private const string CONTEXT = 'sinemacula/laravel-authorization:access-review-cursor';

    /** @var string The format of the review's instant in a cursor, to the microsecond, in UTC. */
    private const string INSTANT = 'Y-m-d\TH:i:s.u\Z';

    /** @var int The longest cursor read, many times the longest one issued; a longer one is refused unread. */
    private const int MAX_LENGTH = 16384;

    /**
     * Create a new cursor codec.
     *
     * @param  string  $key
     * @param  int  $version
     */
    public function __construct(

        /** The key cursors are signed with. */
        private string $key,

        /** The row schema version the cursors are bound to. */
        private int $version = ReviewRow::VERSION,
    ) {}

    /**
     * Return the codec keyed from the application key, refusing to sign or read
     * a cursor when none is set.
     *
     * @return self
     *
     * @throws \Illuminate\Encryption\MissingAppKeyException
     */
    public static function forApplication(): self
    {
        $key = config('app.key');

        if (!\is_string($key) || $key === '') {
            throw new MissingAppKeyException;
        }

        $raw = \str_starts_with($key, 'base64:') ? \base64_decode(\substr($key, 7), true) : $key;

        return new self(\hash_hmac('sha256', self::CONTEXT, $raw === false ? $key : $raw, true));
    }

    /**
     * Return the cursor of the position after a page of the query, bound to the
     * reviewer, or to the trusted path for none.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\Support\ReviewPosition  $position
     * @param  \SineMacula\Laravel\Authorization\Reviews\ReviewQuery  $query
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext|null  $reviewer
     * @return string
     *
     * @throws \JsonException
     */
    public function issue(ReviewPosition $position, ReviewQuery $query, ?ActingContext $reviewer): string
    {
        $after = \array_map(static fn (bool|int|string|null $part): bool|int|string|null => \is_string($part) ? \base64_encode($part) : $part, $position->after ?? []);

        $payload = \json_encode(['v' => $this->version, 'at' => $position->at->utc()->format(self::INSTANT), 'after' => $after], \JSON_THROW_ON_ERROR | \JSON_UNESCAPED_SLASHES);

        return self::encoded($payload) . '.' . self::encoded($this->signature($payload, $query, $reviewer));
    }

    /**
     * Return the position the cursor carries, once its signature is verified
     * for the query and the reviewer, or the trusted path for none.
     *
     * @param  string  $cursor
     * @param  \SineMacula\Laravel\Authorization\Reviews\ReviewQuery  $query
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext|null  $reviewer
     * @return \SineMacula\Laravel\Authorization\Reviews\Support\ReviewPosition
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidReviewCursorException
     */
    public function read(string $cursor, ReviewQuery $query, ?ActingContext $reviewer): ReviewPosition
    {
        $parts = \strlen($cursor) <= self::MAX_LENGTH ? \explode('.', $cursor) : [];

        [$payload, $signature] = \count($parts) === 2 ? [self::decoded($parts[0]), self::decoded($parts[1])] : [null, null];

        if ($payload === null || $signature === null || !\hash_equals($this->signature($payload, $query, $reviewer), $signature)) {
            throw InvalidReviewCursorException::refused();
        }

        return $this->positionOf($payload);
    }

    /**
     * Return the signature of the payload for the query and the reviewer.
     *
     * @param  string  $payload
     * @param  \SineMacula\Laravel\Authorization\Reviews\ReviewQuery  $query
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext|null  $reviewer
     * @return string
     */
    private function signature(string $payload, ReviewQuery $query, ?ActingContext $reviewer): string
    {
        return \hash_hmac('sha256', ReviewOrder::key([$this->binding($query, $reviewer), $payload]), $this->key, true);
    }

    /**
     * Return what a cursor is bound to: the query's kind, scope, application
     * selector, target, subject, window, actor and reach, the action of a
     * filtered review of holdings as one more part, and the reviewer or the
     * trusted path, each part length-prefixed so no two bindings share one, an
     * unfiltered review's binding as it was; the row schema version is bound by
     * the payload, which holds it.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\ReviewQuery  $query
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext|null  $reviewer
     * @return string
     */
    private function binding(ReviewQuery $query, ?ActingContext $reviewer): string
    {
        $scope    = $query->scope;
        $identity = $query->subject?->identity;
        $identity = $identity instanceof Model || $identity instanceof Reference ? Reference::of($identity) : null;

        return ReviewOrder::key([
            $query->kind->value,
            $scope->selection->value,
            ...self::parts($scope->tenant),
            $scope->application->selection(),
            $scope->application->application,
            ...self::parts($query->target),
            $query->subject === null ? 'identity' : 'principal',
            ...self::parts($query->about()),
            ...self::parts($identity),
            $query->from?->format(self::INSTANT),
            $query->until?->format(self::INSTANT),
            ...self::parts($query->actor),
            $query->isDirectOnly ? 'direct' : 'routes',
            ...($query->action === null ? [] : [$query->action]),
            ...($reviewer === null ? ['trusted'] : ['reviewer', ...self::parts($reviewer->principal()), ...self::parts($reviewer->impersonator)]),
        ]);
    }

    /**
     * Return the position the verified payload holds, refusing one of another
     * schema version or of any other shape.
     *
     * @param  string  $payload
     * @return \SineMacula\Laravel\Authorization\Reviews\Support\ReviewPosition
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidReviewCursorException
     */
    private function positionOf(string $payload): ReviewPosition
    {
        $decoded = \json_decode($payload, true);
        $at      = \is_array($decoded) && \is_string($decoded['at'] ?? null) ? self::instantOf($decoded['at']) : null;
        $after   = \is_array($decoded) && \is_array($decoded['after'] ?? null) ? self::keyOf($decoded['after']) : null;

        if ($at === null || $after === null || ($decoded['v'] ?? null) !== $this->version) {
            throw InvalidReviewCursorException::refused();
        }

        return new ReviewPosition($at, $after);
    }

    /**
     * Return the instant the text holds in a cursor's format, in UTC, or null
     * when it holds none.
     *
     * @param  string  $text
     * @return \Carbon\CarbonImmutable|null
     */
    private static function instantOf(string $text): ?CarbonImmutable
    {
        try {
            return CarbonImmutable::createFromFormat(self::INSTANT, $text, 'UTC');
        } catch (\Throwable) {
            return null;
        }
    }

    /**
     * Return the sort key the payload's parts hold, each string decoded; null
     * when they are no sort key: not a list, empty, not led by a kind's
     * position, or holding a part of any other type.
     *
     * @param  array<array-key, mixed>  $parts
     * @return list<bool|int|string|null>|null
     */
    private static function keyOf(array $parts): ?array
    {
        if (!\array_is_list($parts) || !\is_int($parts[0] ?? null)) {
            return null;
        }

        $wrapped = \array_map(static fn (mixed $part): ?array => self::partOf($part), $parts);

        return \in_array(null, $wrapped, true) ? null : \array_map(static fn (array $part): bool|int|string|null => $part[0], $wrapped);
    }

    /**
     * Return the part of a sort key the payload's part holds, wrapped so a null
     * part is told apart from none: a string decoded from base64, an integer, a
     * boolean or a null as it is; null for anything else.
     *
     * @param  mixed  $part
     * @return array{bool|int|string|null}|null
     */
    private static function partOf(mixed $part): ?array
    {
        if (\is_string($part)) {
            $bytes = \base64_decode($part, true);

            return $bytes === false ? null : [$bytes];
        }

        return \is_int($part) || \is_bool($part) || $part === null ? [$part] : null;
    }

    /**
     * Return the parts of a reference in a binding: its type and key, or a null
     * twice for none.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $reference
     * @return list<string|null>
     */
    private static function parts(?Reference $reference): array
    {
        return [$reference?->type, $reference?->id];
    }

    /**
     * Return the bytes base64url-encoded, unpadded.
     *
     * @param  string  $bytes
     * @return string
     */
    private static function encoded(string $bytes): string
    {
        return \rtrim(\strtr(\base64_encode($bytes), '+/', '-_'), '=');
    }

    /**
     * Return the bytes a base64url text encodes, or null when the text is not
     * exactly their canonical encoding: whatever the decoding passes over, a
     * character outside the alphabet, padding or spare bits that are not zero,
     * the text is refused unless encoding the bytes again gives it back.
     *
     * @param  string  $text
     * @return string|null
     */
    private static function decoded(string $text): ?string
    {
        $bytes = \base64_decode(\strtr($text, '-_', '+/'), true);

        return \is_string($bytes) && self::encoded($bytes) === $text ? $bytes : null;
    }
}
