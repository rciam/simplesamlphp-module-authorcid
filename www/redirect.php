<?php

/**
 * Handle redirect call from ORCID.
 */

if (!array_key_exists('state', $_REQUEST)) {
    throw new Exception('ORCID client state information not found');
}
$state = SimpleSAML_Auth_State::loadState($_REQUEST['state'], sspmod_authorcid_Auth_Source_ORCID::STAGE_INIT);

if (array_key_exists('code', $_REQUEST)) {
    $state[sspmod_authorcid_Auth_Source_ORCID::CODE] = $_REQUEST['code'];
} else {
    throw new Exception('ORCID client authorize code not returned.');;
}

// Find authentication source
assert('array_key_exists(sspmod_authorcid_Auth_Source_ORCID::AUTHID, $state)');
$sourceId = $state[sspmod_authorcid_Auth_Source_ORCID::AUTHID];

$source = SimpleSAML_Auth_Source::getById($sourceId);
if ($source === NULL) {
    throw new Exception('Could not find authentication source with id ' . $sourceId);
}

$source->finalStep($state);

SimpleSAML_Auth_Source::completeAuth($state);

