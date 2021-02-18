<?php

/**
 * Handle redirect call from ORCID.
 */

if (!array_key_exists('state', $_REQUEST)) {
    throw new Exception('ORCID client state information not found');
}
$state = SimpleSAML\Auth\State::loadState($_REQUEST['state'], SimpleSAML\Module\authorcid\Auth\Process\ORCID::STAGE_INIT);

if (array_key_exists('code', $_REQUEST)) {
    $state[SimpleSAML\Module\authorcid\Auth\Process\ORCID::CODE] = $_REQUEST['code'];
} else {
    throw new Exception('ORCID client authorize code not returned.');
}

// Find authentication source
assert('array_key_exists(sspmod_authorcid_Auth_Source_ORCID::AUTHID, $state)');
$sourceId = $state[SimpleSAML\Module\authorcid\Auth\Process\ORCID::AUTHID];

$source = SimpleSAML\Auth\Source::getById($sourceId);
if ($source === NULL) {
    throw new Exception('Could not find authentication source with id ' . $sourceId);
}

$source->finalStep($state);

SimpleSAML\Auth\Source::completeAuth($state);
