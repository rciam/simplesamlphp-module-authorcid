<?php

/**
 * Handle redirect call from ORCID.
 */

use SimpleSAML\Auth\Source;
use SimpleSAML\Auth\State;
use SimpleSAML\Module\authorcid\Auth\Source\ORCID;

if (!array_key_exists('state', $_REQUEST)) {
    throw new Exception('ORCID client state information not found');
}
$state = State::loadState($_REQUEST['state'], ORCID::STAGE_INIT);

if (array_key_exists('code', $_REQUEST)) {
    $state[ORCID::CODE] = $_REQUEST['code'];
} else {
    throw new Exception('ORCID client authorize code not returned.');
}

// Find authentication source
assert('array_key_exists(sspmod_authorcid_Auth_Source_ORCID::AUTHID, $state)');
$sourceId = $state[ORCID::AUTHID];

$source = Source::getById($sourceId);
if ($source === null) {
    throw new Exception('Could not find authentication source with id ' . $sourceId);
}

$source->finalStep($state);

Source::completeAuth($state);
