<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Database\Eloquent\Relations\Relation;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authorization\Administration\ActingContext;
use SineMacula\Laravel\Authorization\Console\Support\ActorOption;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature tests for `ActorOption`, which reads the `--actor` option of the
 * commands that write.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(ActorOption::class)]
final class ActorOptionTest extends TestCase
{
    /**
     * Clear the morph map.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Relation::morphMap([], false);

        parent::tearDown();
    }

    /**
     * Without the option the command records no actor.
     *
     * @return void
     */
    public function testNoOptionIsNoActor(): void
    {
        self::assertNull(ActorOption::parse(null));
    }

    /**
     * A command writing through a management service names the actor as an
     * acting context, its subject the actor's row; without the option it names
     * none, and a malformed value or a missing row is refused as for a
     * reference.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    public function testNamesTheActorAsAnActingContext(): void
    {
        $admin = StubIdentity::create(['id' => 'admin-1']);
        $actor = ActorOption::acting(StubIdentity::class . ':admin-1');

        self::assertNull(ActorOption::acting(null));
        self::assertInstanceOf(ActingContext::class, $actor);
        self::assertTrue($admin->is($actor->subject->subject));
        self::assertNull($actor->subject->session);

        foreach (['admin-1', StubIdentity::class . ':missing'] as $value) {
            try {
                ActorOption::acting($value);
                self::fail("'{$value}' was not refused.");
            } catch (\InvalidArgumentException) {
                self::assertTrue(true);
            }
        }
    }

    /**
     * A morph alias is resolved through the morph map, the actor's row is
     * loaded, and the reference names it by its alias.
     *
     * @return void
     */
    public function testResolvesAMorphAlias(): void
    {
        Relation::morphMap(['member' => StubIdentity::class]);

        StubIdentity::query()->create(['id' => 'admin-1']);

        self::assertEquals(new Reference('member', 'admin-1'), ActorOption::parse('member:admin-1'));
    }

    /**
     * A class name is accepted, and the reference names the actor by its morph
     * class under the morph map, not by the class name given.
     *
     * @return void
     */
    public function testNamesAClassByItsMorphClass(): void
    {
        StubIdentity::query()->create(['id' => 'admin:1']);

        self::assertEquals(new Reference(StubIdentity::class, 'admin:1'), ActorOption::parse(StubIdentity::class . ':admin:1'));

        Relation::morphMap(['member' => StubIdentity::class]);

        self::assertEquals(new Reference('member', 'admin:1'), ActorOption::parse(StubIdentity::class . ':admin:1'));
    }

    /**
     * Values that are not in the `{morphType}:{key}` format.
     *
     * @return iterable<string, array{mixed}>
     */
    public static function malformed(): iterable
    {
        yield 'no separator' => ['user'];
        yield 'no type' => [':1'];
        yield 'no key' => ['user:'];
        yield 'empty' => [''];
        yield 'not a string' => [['user:1']];
    }

    /**
     * A value not in the `{morphType}:{key}` format is refused.
     *
     * @param  mixed  $value
     * @return void
     */
    #[DataProvider('malformed')]
    public function testRefusesAMalformedValue(mixed $value): void
    {
        $this->expectExceptionObject(new \InvalidArgumentException('The actor must be in the format {morphType}:{key} (e.g. user:1).'));

        ActorOption::parse($value);
    }

    /**
     * A type that is not an Eloquent model is refused.
     *
     * @return void
     */
    public function testRefusesATypeThatIsNotAModel(): void
    {
        $this->expectExceptionObject(new \InvalidArgumentException('The actor type \'stdClass\' is not an Eloquent model.'));

        ActorOption::parse('stdClass:1');
    }

    /**
     * An actor whose row does not exist is refused, rather than recorded.
     *
     * @return void
     */
    public function testRefusesAnActorThatDoesNotExist(): void
    {
        $this->expectExceptionObject(new \InvalidArgumentException('No actor ' . StubIdentity::class . ' found with key \'ghost\'.'));

        ActorOption::parse(StubIdentity::class . ':ghost');
    }
}
