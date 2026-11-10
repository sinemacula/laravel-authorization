<?php

declare(strict_types = 1);

namespace Tests\Unit\Support;

use Carbon\CarbonImmutable;
use Illuminate\Container\Container;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Routing\Route;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Administration\ActingContext;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Unit tests for `Operation`, one call that changes the package's records.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Operation::class)]
final class OperationTest extends TestCase
{
    /**
     * Reset the clock.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * An operation begun with no actor is trusted: it has a new UUID, no actor,
     * no identity, no impersonator, no actions, and the current time in UTC.
     *
     * @return void
     */
    public function testBeginsTrustedWithANewIdAndTheTimeInUtc(): void
    {
        CarbonImmutable::setTestNow(CarbonImmutable::parse('2026-07-01 14:00:00', 'Europe/Paris'));

        $operation = Operation::begin();

        self::assertMatchesRegularExpression('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/', $operation->id);
        self::assertNull($operation->actor);
        self::assertTrue($operation->isTrusted);
        self::assertNull($operation->identity);
        self::assertNull($operation->impersonator);
        self::assertSame([], $operation->actions);
        self::assertSame('2026-07-01T12:00:00+00:00', $operation->at->format(\DATE_ATOM));
        self::assertSame('UTC', $operation->at->getTimezone()->getName());
    }

    /**
     * Each operation has an id of its own.
     *
     * @return void
     */
    public function testEachOperationHasItsOwnId(): void
    {
        self::assertNotSame(Operation::begin()->id, Operation::begin()->id);
    }

    /**
     * A reference a trusted command names is the actor of a trusted operation,
     * for the record alone.
     *
     * @return void
     */
    public function testAReferenceAttributesATrustedOperation(): void
    {
        $reference = new Reference('user', '7');
        $operation = Operation::begin($reference, [PackagePermissions::PERMISSION_CREATE]);

        self::assertSame($reference, $operation->actor);
        self::assertTrue($operation->isTrusted);
        self::assertNull($operation->identity);
        self::assertSame([PackagePermissions::PERMISSION_CREATE], $operation->actions);
    }

    /**
     * An acting context makes the operation delegated: its actor is the acting
     * principal, with the identity behind it and the impersonator, and its
     * actions are listed once each, in the order given.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    public function testAnActingContextMakesTheOperationDelegated(): void
    {
        $principal = self::saved('42');
        $identity  = self::saved('7');
        $actor     = ActingContext::for(new Subject($principal, $identity))->impersonatedBy(new Reference('support', '3'));
        $operation = Operation::begin($actor, [PackagePermissions::ROLE_GRANT, PackagePermissions::ROLE_REVOKE, PackagePermissions::ROLE_GRANT]);

        self::assertEquals(new Reference('stub', '42'), $operation->actor);
        self::assertEquals(new Reference('stub', '7'), $operation->identity);
        self::assertEquals(new Reference('support', '3'), $operation->impersonator);
        self::assertFalse($operation->isTrusted);
        self::assertSame([PackagePermissions::ROLE_GRANT, PackagePermissions::ROLE_REVOKE], $operation->actions);
    }

    /**
     * A delegated operation begun in a routed request carries the request's IP
     * address and user agent; begun with no routed request, as console and
     * queued work is, it carries none; and a trusted one carries none, even in
     * a routed request.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    public function testADelegatedOperationCarriesTheRoutedRequestsClient(): void
    {
        $actor = ActingContext::for(new Subject(self::saved('42'), self::saved('7')));

        self::withRequest(null, static function () use ($actor): void {
            $operation = Operation::begin($actor);

            self::assertSame([null, null], [$operation->ip, $operation->userAgent]);
        });

        self::withRequest(self::request(false), static function () use ($actor): void {
            $operation = Operation::begin($actor);

            self::assertSame([null, null], [$operation->ip, $operation->userAgent]);
        });

        self::withRequest(self::request(true), static function () use ($actor): void {
            $delegated = Operation::begin($actor);
            $trusted   = Operation::begin(new Reference('user', '7'));

            self::assertSame(['203.0.113.9', 'Browser/1.0'], [$delegated->ip, $delegated->userAgent]);
            self::assertSame([null, null], [$trusted->ip, $trusted->userAgent]);
        });
    }

    /**
     * A client the caller passes is kept as it is, for a trusted operation and
     * for a delegated one in a routed request, whose own client is then not
     * read, even when the caller passes only one of the two values.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    public function testAnExplicitClientIsKept(): void
    {
        $actor = ActingContext::for(new Subject(self::saved('42'), self::saved('7')));

        $trusted = Operation::begin(null, [], '198.51.100.1', 'Worker/2.0');

        self::assertSame(['198.51.100.1', 'Worker/2.0'], [$trusted->ip, $trusted->userAgent]);

        self::withRequest(self::request(true), static function () use ($actor): void {
            $both  = Operation::begin($actor, [], '198.51.100.1', 'Worker/2.0');
            $ip    = Operation::begin($actor, [], '198.51.100.2');
            $agent = Operation::begin($actor, [], null, 'Worker/3.0');

            self::assertSame(['198.51.100.1', 'Worker/2.0'], [$both->ip, $both->userAgent]);
            self::assertSame(['198.51.100.2', null], [$ip->ip, $ip->userAgent]);
            self::assertSame([null, 'Worker/3.0'], [$agent->ip, $agent->userAgent]);
        });

        $built = new Operation('op', null, new \DateTimeImmutable, true, null, null, [], '192.0.2.1', 'Agent/4.0');

        self::assertSame(['192.0.2.1', 'Agent/4.0'], [$built->ip, $built->userAgent]);
        self::assertSame([null, null], [(new Operation('op', null, new \DateTimeImmutable))->ip, (new Operation('op', null, new \DateTimeImmutable))->userAgent]);
    }

    /**
     * An operation without its client keeps everything else, and one with no
     * client is returned as it is.
     *
     * @return void
     */
    public function testWithoutClientKeepsEverythingElse(): void
    {
        $operation = new Operation(
            'op',
            new Reference('user', '1'),
            new \DateTimeImmutable('@100'),
            false,
            new Reference('id', '2'),
            new Reference('support', '3'),
            ['a', 'b'],
            '192.0.2.1',
            'Agent/4.0',
        );
        $stripped = $operation->withoutClient();
        $plain    = Operation::begin();

        self::assertSame([null, null], [$stripped->ip, $stripped->userAgent]);
        self::assertSame(
            [$operation->id, $operation->actor, $operation->at, $operation->isTrusted, $operation->identity, $operation->impersonator, $operation->actions],
            [$stripped->id, $stripped->actor, $stripped->at, $stripped->isTrusted, $stripped->identity, $stripped->impersonator, $stripped->actions],
        );
        self::assertSame($plain, $plain->withoutClient());
        self::assertNull((new Operation('op', null, new \DateTimeImmutable, true, null, null, [], '192.0.2.1'))->withoutClient()->ip);
        self::assertNull((new Operation('op', null, new \DateTimeImmutable, true, null, null, [], null, 'Agent/4.0'))->withoutClient()->userAgent);
    }

    /**
     * Run the callback with a container holding the request as the current one,
     * or none, and put the container in place back afterwards.
     *
     * @param  \Illuminate\Http\Request|null  $request
     * @param  \Closure(): void  $callback
     * @return void
     */
    private static function withRequest(?Request $request, \Closure $callback): void
    {
        $previous  = Container::getInstance();
        $container = new Container;

        if ($request !== null) {
            $container->instance('request', $request);
        }

        Container::setInstance($container);

        try {
            $callback();
        } finally {
            Container::setInstance($previous);
        }
    }

    /**
     * Return a request from a client with an IP address and a user agent,
     * routed or not.
     *
     * @param  bool  $isRouted
     * @return \Illuminate\Http\Request
     */
    private static function request(bool $isRouted): Request
    {
        $request = Request::create('/posts', 'GET', [], [], [], ['REMOTE_ADDR' => '203.0.113.9', 'HTTP_USER_AGENT' => 'Browser/1.0']);

        if ($isRouted) {
            $request->setRouteResolver(static fn (): Route => new Route('GET', '/posts', static fn (): null => null));
        }

        return $request;
    }

    /**
     * Return a model that reads as saved, with the key.
     *
     * @param  string  $key
     * @return \Illuminate\Database\Eloquent\Model
     */
    private static function saved(string $key): Model
    {
        $model = new class extends Model {
            /** @var string Primary key type. */
            protected $keyType = 'string';

            /**
             * Return the model's morph type, short whatever path declares it.
             *
             * @return string
             */
            #[\Override]
            public function getMorphClass(): string
            {
                return 'stub';
            }
        };

        $model->forceFill(['id' => $key]);
        $model->exists = true;

        return $model;
    }
}
