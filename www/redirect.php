<?php

use SimpleSAML\Auth\State;
use SimpleSAML\Auth\Source;

/**
 * Handle redirect call from ORCID.
 */

if (!array_key_exists('state', $_REQUEST)) {
    throw new Exception('ORCID client state information not found');
}
$state = State::loadState($_REQUEST['state'], SimpleSAML\Module\authorcid\Auth\Source\ORCID::STAGE_INIT);

if (array_key_exists('code', $_REQUEST)) {
    $state[SimpleSAML\Module\authorcid\Auth\Source\ORCID::CODE] = $_REQUEST['code'];
} else {
    throw new Exception('ORCID client authorize code not returned.');;
}

// Find authentication source
assert('array_key_exists(SimpleSAML\Module\authorcid\Auth\Source\ORCID::AUTHID, $state)');
$sourceId = $state[SimpleSAML\Module\authorcid\Auth\Source\ORCID::AUTHID];

$source = Source::getById($sourceId);
if ($source === NULL) {
    throw new Exception('Could not find authentication source with id ' . $sourceId);
}

$source->finalStep($state);

Source::completeAuth($state);

