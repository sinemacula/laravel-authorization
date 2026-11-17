# Octane and long-lived workers

The package keeps what it learns for one unit of work: a request, a queued job or a console command. Everything it holds
for one is bound with `scoped()`, so Laravel's queue worker forgets it before each job and Octane builds it afresh on
each request's sandbox, and no subject, tenant, session or resolution reaches the next unit.

## What is scoped

| State                                                                                  | Lives                          |
|----------------------------------------------------------------------------------------|--------------------------------|
| The manager (`authorization`) and every scoped manager it builds                       | One unit of work               |
| The last decision and what the unit remembers towards its decisions                    | One unit of work               |
| The resolved tenant, its application and its ancestors                                 | One unit of work               |
| The resolution cache's memo (see [Caching](caching.md))                                | One unit of work               |
| The default, or the class your configuration names, of each seam but the key catalogue | One unit of work               |
| The trusted context sources, the check context factory and the session scope map       | One unit of work               |
| Whether break-glass is enabled, the abilities the Gate answers for, the preview state  | One unit of work               |
| The package's state after boot, the binding records and the sibling declarations       | The process                    |
| The context key catalogue, and every key a service provider registers on it            | The process                    |
| The management services, `ApplicationAccess`, `GrantScopeQuery` and `AccessReview`     | The process, holding no state  |
| The grant usage recorder                                                               | The container that resolved it |

The settings read once a unit of work, the cache's and `break_glass.enabled` among them, are seen changed from the next
one. The usage recorder is resolved once by a queue worker or a command, and by each Octane sandbox for itself, and
sends what it noted as each request, command and queued job ends (see [Usage
tracking](access-reviews.md#usage-tracking)).

The package's state after boot is changed in place, so an Octane sandbox cloned from the application sees it. An
application whose boot threw and that goes on to serve another request refuses every operation rather than run
unvalidated (see [The diagnostic boot](console.md#the-diagnostic-boot)).

## Your own bindings

A class you name in `config/authorization.php` is built for each unit of work, as the default it replaces is. A binding
you make on a contract yourself is kept exactly as you made it, across every reset (see
[Configuration](configuration.md)): one bound with `singleton()` or `instance()` lives as long as the process. Bind a
class that reads the request, the signed-in user or the session with `scoped()`, so each unit builds its own:

```php
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;

$this->app->scoped(SubjectResolver::class, App\Authorization\CurrentSubject::class);
```

A singleton that holds a scoped instance keeps the instance of the unit it was built in, the package's manager or a
resolver among them, so never inject a scoped instance into a singleton. Rebinding the subject resolver or the tenant
tree during a unit empties the resolution cache's memo, since what it holds was resolved through the binding replaced. A
sibling package declares how long its adapter lives when it declares the adapter (see [For suite
packages](console.md#checking-the-configuration)).

## Within one unit of work

The memo, the resolved tenant and the last decision last the whole unit. A write the unit makes through the package
empties the memo, so its next check reads afresh. A write another worker makes is read from this worker's next unit, or,
within the one running, once the memo entry it changed lapses, `cache.ttl` seconds at most (see
[Invalidation](caching.md#invalidation)).

When a proof is recorded or revoked, a session signs in or out, or the tenant is switched inside a unit, call
`Authorization::forgetDecisionsFor()`, so the rest of it decides afresh (see [Forgetting
decisions](context.md#forgetting-decisions)). It forgets for every session and identity, and never touches the store.

## Long-running commands

A console command is one unit of work for as long as it runs: its memo, resolved tenant and last decision are kept from
its first check to its last, and the usage recorder sends what it noted only as it ends. A command that does several
units of work in one process calls `Support\RequestState::forget($app)` between them. It forgets the scoped instances
held under the package's own names and nothing else, so what Laravel or another package keeps scoped for the command,
such as its context or the callbacks deferred with `defer()`, stands; `RequestState::abstracts($app)` lists what it
would forget (see [Resetting between units of work](console.md#checking-the-configuration)). It clears the manager the
`Authorization` facade resolved too, so the facade's next call reaches a fresh one.

## Example: a command that works through every account

A nightly command checks, for each account, whether its owner may still export reports there. Forgetting between
accounts keeps the memo from holding an entry for every owner checked, and lets a change written by another worker
meanwhile reach the next account at once:

```php
use App\Models\Account;
use Illuminate\Console\Command;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\RequestState;

final class AuditExports extends Command
{
    protected $signature = 'reports:audit-exports';

    public function handle(): int
    {
        foreach (Account::query()->with('owner')->lazyById() as $account) {
            $owner = new Subject($account->owner, $account->owner, $account);

            if (Authorization::for($owner)->cannot('reports:export')) {
                $account->disableScheduledExports();
            }

            RequestState::forget($this->laravel);
        }

        return self::SUCCESS;
    }
}
```

Each check is decided in its account, as the `Subject` names it. The next account builds a fresh manager, memo and
resolved tenant, and reads its owner's grants from the store while their versions hold, else from the database. Run as a
queued job per account instead, the worker forgets the same state before each job by itself.
