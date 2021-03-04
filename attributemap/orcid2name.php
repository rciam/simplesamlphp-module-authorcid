<?php

$attributemap = [

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
];
