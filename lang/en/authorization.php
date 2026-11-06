<?php

declare(strict_types = 1);

return [

    /*
    |---------------------------------------------------------------------------
    | Authorization Language Lines
    |---------------------------------------------------------------------------
    |
    | Messages the package can put in front of a client. They load under the
    | `authorization` namespace; publish them with the `authorization-lang` tag
    | to reword them or to add a locale.
    |
    | Every denial carries the one `denied` line, whatever its reason. The
    | reason code travels beside it, on the exception and the policy response,
    | so an application that wants a message per reason words it from the code.
    | A route middleware answering a request without a subject carries the
    | `unauthenticated` line.
    |
    */

    'denied' => 'This action is unauthorized.',

    'unauthenticated' => 'Unauthenticated.',

];
