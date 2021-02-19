# simplesamlphp-module-authorcid

A SimpleSAMLphp authentication module for enabling users to sign in with their ORCID accounts using their registered email address and password (or alternative sign in account) and then authorise access to their ORCID iD.

This SimpleSAMLphp authentication source can be configured to use either the **Public** or **Member** ORCID API to allow users to sign in with their ORCID account. Accessing the ORCID API requires a set of client credentials consisting of a **Client ID** and a **Client Secret**.

You can configure credentials for the Public API from a personal ORCID
account. You can then use this authentication source to retrieve a user's
authenticated ORCID iD and a JSON-formatted version of their public ORCID
record. Member API clients have access to additional scopes to read-limited information (or write) to an ORCID record.

## Installation

This module requires the cURL PHP extension.

### Clone repository

Clone this repository into the `modules` directory of your SimpleSAMLphp
installation as follows:

```shell
cd /path/to/simplesamlphp/modules
git clone https://github.com/rciam/simplesamlphp-module-authorcid.git authorcid
🍺
```

## Configuration

The configuration options for this authentication source are specified below:

* `clientId`: REQUIRED. Your Public or Member API client id (e.g. `APP-F6TMYF419CVYMSNE`).
* `clientSecret`: REQUIRED. Your Public or Member API client secret.
* `authorizeEndpoint`: OPTIONAL, defaults to `https://orcid.org/oauth/authorize`. URL of ORCID's OAuth 2.0 Authorization Endpoint.
* `tokenEndpoint`: OPTIONAL, defaults to `https://orcid.org/oauth/token`. URL of ORCID's OAuth 2.0 Token Endpoint.
* `userInfoEndpoint`: OPTIONAL, defaults to `https://pub.orcid.org/v3.0`. Base URL of ORCID's Record API: `[userInfoEndpoint]/[orcidId]/record`.
* `scope`: OPTIONAL, defaults to `/authenticate`. String representing the permission of access requested by the client application configured for this authentication source. Both Public and Member API client can use `/authenticate`. Member API clients have access to additional scopes to read-limited information or write to an ORCID record. Specifically:
  * `/authenticate`: Allows the client application to obtain the record holder's 16-character ORCID iD and read public information on that ORCID record.  
  * `/read-limited`: Allows the client application to obtain the record holder's ORCID iD and read public and limited access information on that ORCID record.

The table below lists the configuration options for the production ORCID environment. Note that some settings are common to both the Public and the Member ORCID API.

| Config Option        | Config Value  | Production ORCID API Version |
| :------------------- | :------------ | :------------------- |
| `authorizeEndpoint`  | `https://orcid.org/oauth/authorize` | Public or Member |
| `tokenEndpoint`      | `https://orcid.org/oauth/token`     | Public or Member |
| `userInfoEndpoint`   | 1. `https://pub.orcid.org/v3.0` <br/> 2. `https://api.orcid.org/v3.0` | 1. Public <br/> 2. Member |
| `scope`   | 1. `/authenticate` <br/> 2. `/read-limited` | 1. Public or Member <br/> 2. Member |

In addition to the production ORCID APIs, ORCID also offers a test environment, called the **Sandbox**. This allows testing client applications without accessing data in the live ORCID registry. The configuration values for testing this authentication source against the Sandbox environment are listed in the following table.

| Config Option        | Config Value  | Sandbox ORCID API Version |
| :------------------- | :------------ | :---------------- |
| `authorizeEndpoint`  | `https://sandbox.orcid.org/oauth/authorize` | Public or Member |
| `tokenEndpoint`      | `https://sandbox.orcid.org/oauth/token`     | Public or Member |
| `userInfoEndpoint`   | 1. `https://pub.sandbox.orcid.org/v3.0` <br/> 2. `https://api.sandbox.orcid.org/v3.0` | 1. Public <br/> 2. Member |
| `scope`   | 1. `/authenticate` <br/> 2. `/read-limited` | 1. Public or Member <br/> 2. Member |

### Example authentication source configuration

#### Public ORCID API client

Adjust the configuration below according to your Public ORCID API client credentials to retrieve a user's authenticated ORCID iD and a JSON-formatted version of their public ORCID record from the production ORCID registry.

```php
'orcid' => [
    'authorcid:ORCID',
    'clientId' => 'APP-XXXXXXXXXXXXXXXX',
    'clientSecret' => 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx',
],
```

#### Member ORCID API client

Adjust the configuration below according to your Member ORCID API client credentials to retrieve a user's authenticated ORCID iD and a JSON-formatted version of their public and read-limited ORCID record from the production ORCID registry:

```php
'orcid' => [
    'authorcid:ORCID',
    'clientId' => 'APP-XXXXXXXXXXXXXXXX',
    'clientSecret' => 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx',
    'scope' => '/read-limited',
    'userInfoEndpoint' => 'https://api.orcid.org/v3.0',
],
```

### Example attribute mapping configuration

Use the configuration below to update the user's attributes in the SimpleSAMLphp `$state` array based on the retrieved ORCID record data:

```php
<?php
$attributemap = [
    // Attributes returned by ORCID
    'orcid.uri'             => 'eduPersonOrcid',        // URI with a 16-digit number
                                                        // compatible with ISO 27729,
                                                        // a.k.a. International Standard 
                                                        // Name Identifier (ISNI)
    'orcid.path'            => 'uid',                   // The ORCID number formatted as
                                                        // xxxx-xxxx-xxxx-xxxx
    'orcid.name'            => 'displayName',           // Published name
    'orcid.given-names'     => 'givenName',             // First name
    'orcid.family-name'     => 'sn',                    // Last name
    'orcid.email'           => 'mail',                  // Primary email address
    'orcid.verified-emails' => 'voPersonVerifiedEmail', // Verified email address(es)
];
```

## Compatibility matrix

The table below matches the module version with the supported SimpleSAMLphp version.

| Module | SimpleSAMLphp |
|:------:|:-------------:|
| v1.0   | v1.14         |
| v1.1   | v1.14         |

## License

Licensed under the Apache 2.0 license, for details see `LICENSE`.
