# Permission Catalogue Sync

The application declares its platform permissions in code: the cases of string-backed enums implementing
`PermissionEnum`, and the definitions returned by classes implementing `PermissionProvider`. `authorization:sync`
writes that catalogue to the `permissions` table on deploy, with the permissions the package declares for its own
services. Booting the package never touches the database, and reads the enums and providers only to check that the
actions named by `authorization.session.scopes` or `authorization.events.decisions.sensitive_actions` are declared,
when either names one. This note documents what the sync changes, what it only reports, and how it fails.

## Invariants

1. **Booting never touches the database.** The service provider registers the Gate hook and validates the configured
   classes, but never queries or writes a table, nor reads an enum or a provider for the hook, which reads the
   catalogue on the first Gate check, so `config:cache`, `route:cache` and `migrate` run on a fresh database with
   enums and providers configured. `authorization:sync` is the only path that writes the catalogue.

2. **An enum case's value is the permission name.** `PermissionEnum` extends `\BackedEnum`, so a unit enum cannot
   implement it, and the config validation refuses, at boot, an enum backed by integers. Callers read `->value`.

3. **Names follow the package's name rules.** Every declared name is checked against the configured permission model's
   rule (letters, digits and `_ - : . *`, at most 191 characters) when the catalogue is read. A name that breaks it
   fails the sync before anything is written.

4. **Stale rows are reported, not removed.** A platform permission that no enum or provider declares is listed as
   `stale` and left alone, because it may have been imported, created by hand or declared by a provider that is not
   installed in every environment. Only `--prune` deletes stale rows. There is no deprecation column: a permission is
   either in the catalogue or reported as stale.

5. **System rows are never changed.** A system row refuses every edit and delete without an explicit override
   (`forceSystem()`). When one is stale, or declared with a different description or category, the sync lists it as
   `protected` and leaves it as it is, with or without `--prune`.

6. **Only platform rows take part.** The sync reads the rows whose tenant columns are null, bypassing the tenant scope.
   Tenant-owned permissions are never read, listed or changed, even when one shares a declared name.

7. **Every write goes through the configured model, in one transaction.** Additions, updates and deletions use the
   class in `authorization.models.permission`, so its observers and events run, and happen inside one transaction on
   the package's connection (`authorization.connection`, else the default), as one operation whose events are
   dispatched once it commits. A failure part-way rolls back every write and dispatches nothing.

8. **The package's own permissions are always declared.** `Support\PackagePermissions`, the package's own provider,
   comes first in every catalogue, whatever the application configures: the administration actions of delegated
   administration (see [Delegated administration](delegated-administration.md)), `authorization:role.grant`,
   `authorization:guardrail.manage`, the right `GuardrailService` checks, and the rest, each guard-agnostic and under
   the `authorization` category. The sync adds and updates them as any declared permission, so they can be
   granted, and the policy validator accepts a pattern covering any of them, so a policy naming them validates. The
   action catalogue the validator asks (`DeclaredActionCatalogue`) leaves them out, so it holds the application's
   declarations alone, and with none a policy needing any other action is still refused because nothing is declared.
   The Gate asks the package about them as about every declared permission. An application declaration of the
   same name, also guard-agnostic, is merged with it as any duplicate is, and refused when its description or category
   differ.

## Declaring the Catalogue

```php
use SineMacula\Laravel\Authorization\Attributes\Permission as PermissionMeta;
use SineMacula\Laravel\Authorization\Contracts\PermissionEnum;

enum ApplicationPermission: string implements PermissionEnum
{
    #[PermissionMeta(description: 'View applications', category: 'Applications', guards: ['web', 'api'])]
    case VIEW = 'applications:view';

    #[PermissionMeta(description: 'Edit applications', category: 'Applications')]
    case EDIT = 'applications:edit';

    case EXPORT = 'applications:export';
}
```

A case without `guards` declares one guard-agnostic permission (a null `guard`); a list declares one permission per
guard; an empty list declares nothing and is refused, as is a guard that is not a non-empty string (`null` included). An
attribute that cannot be instantiated, because it is repeated or given an argument of the wrong type, is refused too. A
case without the attribute is a guard-agnostic permission with no description or category. The attribute shares its
short name with the permission model, so applications alias it.

A provider returns `PermissionDefinition` objects, each a name, description, category and guard:

```php
use SineMacula\Laravel\Authorization\Contracts\PermissionProvider;
use SineMacula\Laravel\Authorization\Support\PermissionDefinition;

final class BillingPermissions implements PermissionProvider
{
    public function permissions(): array
    {
        return [
            new PermissionDefinition(name: 'billing:view', description: 'View invoices', category: 'Billing'),
        ];
    }
}
```

Providers are resolved through the container, so they can take dependencies. A provider's permissions are answered
through the Gate like an enum's, since the Gate hook reads the catalogue (see [Gate Authority](gate-authority.md)),
and listed by `permissionsFor()` like an enum's, since it lists the catalogue (see
[Effective Permissions](effective-permissions.md)). A permission declared twice for the same guard is kept once when
both declarations agree, and refused when their description or category differ. The configuration is read when the
catalogue is, after boot, so both lists are checked again as boot checks them before anything is read or resolved: an
entry of `authorization.permission_enums` or `authorization.permission_providers` that boot would refuse is refused
with `InvalidAuthorizationConfigException`, never skipped.

## Sync Command

```text
authorization:sync
    [--dry-run]                   Report what would change without writing
    [--format=table|json]         Output format (default: table)
    [--prune]                     Delete stale permissions that are not marked system
    [--actor={morphType}:{key}]   The actor the events record; none for system work
```

`--actor` names a row that must exist, and is only recorded: the sync is trusted work, and decides nothing as the
actor.

Run it in the deployment, after the migrations:

```bash
php artisan migrate --force
php artisan authorization:sync
```

### Algorithm

1. Refuse an unknown `--format`, then validate the configuration as boot does.
2. Read the catalogue (`PermissionCatalogue`): every case of every configured enum, through `PermissionMetadataReader`,
   then every provider's definitions, checking names and guards and merging duplicates.
3. Open a transaction on the package's connection, as one operation, and load the platform rows.
4. Build the diff (`PermissionDiffBuilder`), matching on name and guard:
    - **add**: declared, with no row.
    - **update**: declared, with a row whose description or category differs.
    - **stale**: a row no enum or provider declares, not marked system. Listed as **prune** under `--prune`.
    - **protected**: a system row that is stale, or declared with a different description or category.
    - **unchanged**: declared, with a row that already matches.
5. Unless this is a dry run, insert the additions, update the differing rows and, under `--prune`, delete the stale
   rows, each through the model.
6. Commit, dispatching the operation's events, then list every row with its action, ordered by action, then name,
   then guard (guard-agnostic first).

The JSON output carries `dry_run`, `prune`, a `summary` with a count for each of the six actions, and `permissions`,
one entry per row with its `action`, `name`, `guard`, `description` and `category`.

### Exit Codes

| Code | Meaning                                                                                                  |
|------|----------------------------------------------------------------------------------------------------------|
| 0    | Success, including a dry run that finds nothing to add, update or prune                                  |
| 1    | `--dry-run` found something to add, update or (under `--prune`) prune, so CI can detect drift            |
| 2    | A fatal error: an invalid catalogue or configuration, an unknown format, or a failed write (rolled back) |

A stale row is drift only under `--prune`, since without it the sync would leave the row alone; run
`--dry-run --prune` in CI to fail on stale rows too.

## Failure / Edge Cases

- A name outside the name rules, an empty guard list, a guard that is not a non-empty string, a `#[Permission]`
  attribute that cannot be instantiated, a provider returning anything but definitions, or a conflicting duplicate
  fails with exit code 2 and an error naming the enum case or provider at fault. Nothing is written.
- A write that fails part-way (a database error, or an observer or model event listener that throws) rolls back the
  whole transaction, dispatches nothing and exits with 2.
- Pruning deletes the row through the model; the grants of that permission go with it through the foreign keys. The
  deletion is reported by the model's `Permission\Deleted` event, which names every grantee that held the permission
  directly and every role that carried it.
- The sync never changes a row's name, guard, system flag or tenant columns. Renaming a case adds a new permission and
  reports the old one as stale.

## Implementation Anchors

- Contract: `src/Contracts/PermissionEnum.php`, `src/Contracts/PermissionProvider.php`
- Attribute: `src/Attributes/Permission.php`
- Definition: `src/Support/PermissionDefinition.php`
- Reader: `src/Support/PermissionMetadataReader.php`
- Catalogue: `src/Support/PermissionCatalogue.php`; the package's own permissions: `src/Support/PackagePermissions.php`
- Policy actions: `src/Support/DeclaredActionCatalogue.php`, the declared names a policy's `actions` and `not_actions`
  patterns must match when it is written
- Diff: `src/Console/Support/PermissionDiffBuilder.php`, `src/Console/Support/PermissionDiff.php`
- Command: `src/Console/SyncPermissionsCommand.php`
- Exception: `src/Exceptions/InvalidPermissionCatalogueException.php`
- Actor option: `src/Console/Support/ActorOption.php`
- Boot validation: `src/Config/ConfigValidator.php`

## Authoritative Tests

- `tests/Feature/SyncPermissionsCommandTest.php`: additions, updates, stale reports, pruning with observers, protected
  system rows, tenant rows, dry-run exit codes, JSON, invalid names and formats, the configured model and connection,
  rollback, and the one operation and its `--actor`.
- `tests/Feature/PermissionCatalogueTest.php`, `tests/Feature/PermissionDiffBuilderTest.php`,
  `tests/Unit/Support/PackagePermissionsTest.php`.
- `tests/Unit/Support/PermissionMetadataReaderTest.php`, `tests/Unit/Support/PermissionDefinitionTest.php`.
- `tests/Feature/NoDatabaseAtBootTest.php`: booting with an enum and a provider and no tables runs no query.
- `tests/Feature/ConfigValidatorTest.php`: enums backed by integers are refused at boot.

## Change Triggers

Update this note when any of the following changes:

- The `#[Permission]` attribute or `PermissionDefinition` gains or loses a field.
- An action is added or changes meaning, or the exit codes change.
- Pruning moves to the services, or the treatment of system or tenant-owned rows changes.
- The sync gains or loses a flag.
