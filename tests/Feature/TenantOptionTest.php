<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Database\Eloquent\Relations\Relation;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Console\Support\TenantOption;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Feature\Stubs\StubTenant;
use Tests\TestCase;

/**
 * Feature tests for a console option naming a tenant: a model's row by its
 * morph class, any other type as given, and anything else refused with a
 * message naming the option, never the failure.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(TenantOption::class)]
final class TenantOptionTest extends TestCase
{
    /**
     * A type that names no model is the reference as given, its key holding any
     * colon after the first; a model's row is named by its morph class.
     *
     * @return void
     */
    public function testATenantIsReadAsGivenOrAsItsRow(): void
    {
        self::assertEquals(new Reference('team', 'a:b'), TenantOption::reference('tenant', 'team:a:b'));

        StubTenant::query()->create(['id' => 'tenant-1']);

        Relation::morphMap(['stub-tenant' => StubTenant::class]);

        try {
            self::assertEquals(new Reference('stub-tenant', 'tenant-1'), TenantOption::reference('rooted-within', StubTenant::class . ':tenant-1'));
            self::assertEquals(new Reference('stub-tenant', 'tenant-1'), TenantOption::reference('rooted-within', 'stub-tenant:tenant-1'));

            // An alias the morph map resolves names the model's row, which must
            // exist, as its class does.
            self::assertRefused(static fn (): mixed => TenantOption::reference('tenant', 'stub-tenant:missing'), 'The --tenant option names no saved row.');
        } finally {
            Relation::morphMap([], false);
        }
    }

    /**
     * A value not in the format, a row that is missing, and a lookup that fails
     * are each refused, naming the option given and never its value.
     *
     * @return void
     */
    public function testAnythingElseIsRefusedNamingTheOption(): void
    {
        $format = 'The --rooted-within option must be in the format {morphType}:{key} (e.g. team:1).';

        foreach (['', 'team', ':1', 'team:', 42, null] as $value) {
            self::assertRefused(static fn (): mixed => TenantOption::reference('rooted-within', $value), $format);
        }

        self::assertRefused(static fn (): mixed => TenantOption::reference('tenant', StubTenant::class . ':missing'), 'The --tenant option names no saved row.');

        StubTenant::query()->create(['id' => 'tenant-2']);

        StubTenant::retrieved(static function (): never {
            throw new \RuntimeException('secret');
        });

        self::assertRefused(static fn (): mixed => TenantOption::reference('rooted-within', StubTenant::class . ':tenant-2'), 'The --rooted-within option could not be resolved.');
    }

    /**
     * Assert the callback is refused with the message.
     *
     * @param  \Closure(): mixed  $callback
     * @param  string  $message
     * @return void
     */
    private static function assertRefused(\Closure $callback, string $message): void
    {
        try {
            $callback();
            self::fail('A tenant option was read that should be refused.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame($message, $exception->getMessage());
        }
    }
}
