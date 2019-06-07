# simplesamlphp-module-authorcid
A SimpleSAMLphp module for authenticating users' ORCID iDs and retrieving publicly-visible information from the ORCID registry.

This authentication source uses the ORCID Public API to allow users to sign
in with their ORCID username and password. Accessing the Public API requires
a set of credentials consisting of a **Client ID** and a **Client Secret**. 
You can configure credentials for the Public API from your personal ORCID 
account. You can then use this authentication source to retrieve a user's 
authenticated ORCID iD and a JSON-formatted version of their public ORCID 
record.

## User attributes
To this end, the ORCID authentication source attempts to extract the following attributes from the user's **public** ORCID record:
 * `orcid.uri`: the full path to the ORCID record
 * `orcid.path`: just the 16 digit ORCID identifier
 * `orcid.host`: the domain of the uri, i.e. `orcid.org`
 * `orcid.name`: the user's preferred name
 * `orcid.given-names`: the user's given name, or the name they most commonly 
    go by
 * `orcid.family-name`: the user's family name or surname
 * `orcid.email`: the user's primary email address

## Example authentication source configuration:
```
    'orcid' => array(
        'authorcid:ORCID',
        'clientId' => 'APP-XXXXXXXXXXXXXXXX',
        'clientSecret' => 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx',
    ),
```

## Example attribute mapping configuration
```
<?php
$attributemap = array(

    // Attributes returned by ORCID
    'orcid.uri'          => 'eduPersonOrcid', // URI with a 16-digit number 
                                              // compatible with ISO 27729, 
                                              // a.k.a. International Standard 
                                              // Name Identifier (ISNI)
    'orcid.path'         => 'uid',            // The ORCID number formatted as
                                              // xxxx-xxxx-xxxx-xxxx 
    'orcid.name'         => 'displayName',
    'orcid.given-names'  => 'givenName',
    'orcid.family-name'  => 'sn',
    'orcid.email'        => 'mail',
);
```

## Compatibility matrix
This table matches the module version with the supported SimpleSAMLphp version.
| Module |  SimpleSAMLphp |
|:------:|:--------------:|
| v1.0.0 | v1.14          |
| v1.1.0 | v1.14          |
| v1.2.0 | v1.17          |

## License
Licensed under the Apache 2.0 license, for details see `LICENSE`.
