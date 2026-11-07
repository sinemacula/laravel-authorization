<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Cache;

use Illuminate\Support\Carbon;

/**
 * The in-memory tier of the resolution cache.
 *
 * Holds each resolved list with the instant it lapses, so a temporal grant
 * stops being served at the same point in a long request, job or command as it
 * does from the persistent tier. The memo lives as long as the resolution cache
 * that owns it, which the service provider binds per request or job.
 *
 * Its entries hold in one scope (a tenant, whether checks are decided just
 * below it, and an application), so they are dropped whenever the scope
 * changes, unless they were set aside for a callback run in another scope (see
 * `aside()`), which puts them back once it returns. While a batch of checks is
 * open, they are kept for each scope instead: the entries of the scope left are
 * set aside under its key, and those of the scope entered are taken back once
 * it is read again, so a batch reads what each scope resolves to once, however
 * often its checks move between scopes. A write drops the entries of every
 * scope, so the next check reads afresh in any of them; once the outermost
 * batch closes, the entries set aside are dropped, and the current ones too
 * when the scope changed since they were taken.
 *
 * While a batch is open, the memo also holds what the tenant tree answered, a
 * tenant's ancestors and whether a tenant is within another, which holds in
 * every scope, so a batch asks the tree each question once. A write, a change
 * to the tree reported among them, drops those answers too, and so does the
 * outermost batch closing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class ResolutionMemo
{
    /** @var array<string, array{value: array<int, mixed>, expires_at: int|null}> Entries keyed by full cache key; `expires_at` is the timestamp the entry lapses at, null for never. */
    private array $entries = [];

    /** @var array<string, array<string, array{value: array<int, mixed>, expires_at: int|null}>> While a batch is open, the entries of each scope left, keyed by the scope's key. */
    private array $parked = [];

    /** @var string|null While a batch is open, the key of the scope the entries hold in; null until it is read. */
    private ?string $scope = null;

    /** @var bool Whether the scope changed since the entries were taken, so the next read takes those of the scope entered. */
    private bool $isScopeChanged = false;

    /** @var int How many batches are open, nested in one another. */
    private int $batches = 0;

    /** @var bool Whether the scope's key is being read, which may itself read the memo, while the subject is resolved. */
    private bool $isTakingScope = false;

    /** @var array<string, mixed> While a batch is open, what the tenant tree answered, keyed by the question. */
    private array $answers = [];

    /** @var object A token replaced whenever every entry is dropped, so entries set aside are put back only while it is the one they were set aside under. */
    private object $generation;

    /**
     * Create a new memo.
     *
     * @param  (\Closure(): string)|null  $scopeKey
     */
    public function __construct(

        /** Returns the key of the current scope; null keeps no scope apart, so every change of scope drops the entries. */
        private readonly ?\Closure $scopeKey = null,
    ) {
        $this->generation = new \stdClass;
    }

    /**
     * Return the entry for the key, or null when there is none or it has
     * lapsed.
     *
     * @param  string  $key
     * @return array<int, mixed>|null
     */
    public function get(string $key): ?array
    {
        $this->takeScope();

        if (!isset($this->entries[$key]) || $this->lapsed($key)) {
            return null;
        }

        return $this->entries[$key]['value'];
    }

    /**
     * Determine whether the key holds an entry that has lapsed, as opposed to a
     * live entry or none at all.
     *
     * @param  string  $key
     * @return bool
     */
    public function lapsed(string $key): bool
    {
        $this->takeScope();

        $expiresAt = $this->entries[$key]['expires_at'] ?? null;

        return $expiresAt !== null && self::now() >= $expiresAt;
    }

    /**
     * Store an entry that lapses the given number of seconds from now, or never
     * when the lifetime is null. A lifetime of zero or less stores an entry
     * that has already lapsed.
     *
     * @param  string  $key
     * @param  array<int, mixed>  $value
     * @param  int|null  $lifetime
     * @return void
     */
    public function put(string $key, array $value, ?int $lifetime): void
    {
        $this->takeScope();

        $this->entries[$key] = [
            'value'      => $value,
            'expires_at' => $lifetime === null ? null : self::now() + $lifetime,
        ];
    }

    /**
     * Drop the entry for the key.
     *
     * @param  string  $key
     * @return void
     */
    public function forget(string $key): void
    {
        $this->takeScope();

        unset($this->entries[$key]);
    }

    /**
     * Drop every entry, in every scope.
     *
     * @return void
     */
    public function flush(): void
    {
        $this->generation = new \stdClass;
        $this->entries    = [];
        $this->parked     = [];
        $this->answers    = [];
    }

    /**
     * Return the tenant tree's answer to the question: while a batch is open,
     * the one already given, or the one the callback reads, kept for the rest
     * of the batch, or, asked afresh, the one it reads in place of the one
     * kept; with no batch open, the one it reads, kept for nothing. A callback
     * that throws keeps nothing.
     *
     * @template TAnswer
     *
     * @param  list<string>  $question
     * @param  \Closure(): TAnswer  $answer
     * @param  bool  $isFresh
     * @return TAnswer
     */
    public function tree(array $question, \Closure $answer, bool $isFresh = false): mixed
    {
        if ($this->batches === 0) {
            return $answer();
        }

        $key = \serialize($question);

        if ($isFresh || !\array_key_exists($key, $this->answers)) {
            $this->answers[$key] = $answer();
        }

        return $this->answers[$key];
    }

    /**
     * Note that the scope changed: drop the entries, or, while a batch is open,
     * set them aside under the key of the scope left, so the scope entered
     * takes back its own once it is read.
     *
     * @return void
     */
    public function scopeChanged(): void
    {
        // A scope is only ever taken while a batch is open.
        if ($this->scope !== null) {
            $this->parked[$this->scope] = $this->entries;
        }

        $this->entries        = [];
        $this->scope          = null;
        $this->isScopeChanged = $this->batches > 0;
    }

    /**
     * Run the callback in another scope, keeping the entries of the scope it is
     * run from: they are set aside as it starts and, however it ends, put back
     * once it returns to that scope, unless a write dropped every entry
     * meanwhile, so what the scope resolves to is not read again.
     *
     * @template TResult
     *
     * @param  \Closure(): TResult  $callback
     * @return TResult
     */
    public function aside(\Closure $callback): mixed
    {
        [$entries, $scope, $isScopeChanged, $generation] = [$this->entries, $this->scope, $this->isScopeChanged, $this->generation];

        try {
            return $callback();
        } finally {
            if ($this->generation === $generation) {
                $this->entries        = $entries;
                $this->scope          = $scope;
                $this->isScopeChanged = $isScopeChanged;
            }
        }
    }

    /**
     * Open a batch, within which every scope keeps its entries apart until the
     * outermost batch closes.
     *
     * @return void
     */
    public function open(): void
    {
        $this->batches++;
    }

    /**
     * Close a batch. Once the outermost one closes, the entries set aside are
     * dropped, and the current ones too when the scope changed since they were
     * taken, as they would have been without the batch, and so are the tenant
     * tree's answers.
     *
     * @return void
     */
    public function close(): void
    {
        if ($this->batches > 1) {
            $this->batches--;

            return;
        }

        $this->batches = 0;

        if ($this->isScopeChanged) {
            $this->entries = [];
        }

        $this->parked         = [];
        $this->answers        = [];
        $this->scope          = null;
        $this->isScopeChanged = false;
    }

    /**
     * While a batch is open, read the key of the scope the entries hold in the
     * first time it is needed: the entries already held are the current
     * scope's, unless the scope changed since, when the scope entered takes
     * back those set aside for it. A read of the memo made while the key is
     * read, by a subject resolver reading through the cache say, uses the
     * entries as they are.
     *
     * @return void
     */
    private function takeScope(): void
    {
        if ($this->batches === 0 || $this->scopeKey === null || $this->scope !== null || $this->isTakingScope) {
            return;
        }

        $this->isTakingScope = true;

        try {
            $scope = ($this->scopeKey)();
        } finally {
            $this->isTakingScope = false;
        }

        if ($this->isScopeChanged) {
            $this->entries = $this->parked[$scope] ?? [];

            unset($this->parked[$scope]);
        }

        $this->scope          = $scope;
        $this->isScopeChanged = false;
    }

    /**
     * Return the current Unix timestamp: the test clock when one is set,
     * otherwise the system clock, which is far cheaper to read than Carbon on a
     * path every memo hit takes.
     *
     * @return int
     */
    private static function now(): int
    {
        return Carbon::hasTestNow() ? Carbon::now()->getTimestamp() : \time();
    }
}
