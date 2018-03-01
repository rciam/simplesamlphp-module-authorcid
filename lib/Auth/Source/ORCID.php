<?php

/**
 * Authenticate using ORCID.
 *
 * This authentication source uses the ORCID Public API to allow users to sign
 * in with their ORCID username and password. Accessing the Public API requires
 * a set of credentials consisting of a Client ID and a Client Secret. You can 
 * configure credentials for the Public API from your personal ORCID account.
 * You can then use this authentication source to retrieve a user's 
 * authenticated ORCID iD and a JSON-formatted version of their public ORCID 
 * record.
 *
 * Example authentication source configuration:
 *
 *     'orcid' => array(
 *         'authorcid:ORCID',
 *         'clientId' => 'APP-XXXXXXXXXXXXXXXX',
 *         'clientSecret' => 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx',
 *     ),
 *
 * @author Nicolas Liampotis <nliam@grnet.gr>
 */
class sspmod_authorcid_Auth_Source_ORCID extends SimpleSAML_Auth_Source {
	
    // The string used to identify the init state.
    const STAGE_INIT = 'authorcid:init';

    // The key of the AuthId field in the state.
    const AUTHID = 'authorcid:AuthId';

    // The key of the authZ code in the state.
    const CODE = 'authorcid:code';

    // The authorization endpoint
    private $authorizeEndpoint = 'https://orcid.org/oauth/authorize';

    // The token exchange endpoint
    private $tokenEndpoint = 'https://orcid.org/oauth/token';

    // The user info endpoint
    private $userInfoEndpoint = 'https://pub.orcid.org/v2.1';

    // The ORCID Client redirect URI
    private $redirectURI;

    // The ORCID Client application ID
    private $clientId;

    // The ORCID Client application secret
    private $clientSecret;

    /**
     * Constructor for this authentication source.
     *
     * @param array $info  Information about this authentication source.
     * @param array $config  Configuration.
     */
    public function __construct($info, $config) {
        assert('is_array($info)');
        assert('is_array($config)');

        // Call the parent constructor first, as required by the interface
        parent::__construct($info, $config);

        if (!array_key_exists('clientId', $config)) {
            throw new Exception('ORCID authentication source is not properly configured: Missing clientId');
        }
        $this->clientId = $config['clientId'];

        if (!array_key_exists('clientSecret', $config)) {
            throw new Exception('ORCID authentication source is not properly configured: Missing clientSecret');
        }
        $this->clientSecret = $config['clientSecret'];

        $this->redirectURI = SimpleSAML_Module::getModuleUrl(
            'authorcid/redirect.php');
    }


    /**
     * Authenticate using ORCID credentials
     * Documentation at https://members.orcid.org/orcid-sign-in
     *
     * @param array &$state  Information about the current authentication.
     */
    public function authenticate(&$state) {
        assert('is_array($state)');

        // We are going to need the authId in order to retrieve this 
        // authentication source later
        $state[self::AUTHID] = $this->authId;

        $stateId = SimpleSAML_Auth_State::saveState($state, self::STAGE_INIT, true);
        $authorizeURI = $this->authorizeEndpoint
            . '?client_id=' . $this->clientId
            . '&response_type=code'
            . '&scope=/authenticate'
            . '&show_login=true'
            . '&state=' . $stateId
            . '&redirect_uri=' . $this->redirectURI;

        // Redirect to ORCID authorize endpoint
        SimpleSAML_Utilities::redirect($authorizeURI);
    }


    public function finalStep(&$state) {
        assert('is_array($state)');

        $code = $state[SELF::CODE];
        SimpleSAML_Logger::debug('[authorcid] finalStep: code=' . $code);

        // Exchange ORCID authZ code with access token
        $data = $this->_http('POST', $this->tokenEndpoint,
            array('Accept: application/json'),
            array(
                'client_id' => $this->clientId,
                'client_secret' => $this->clientSecret,
                'grant_type' => 'authorization_code',
                'code' => $code,
                'redirect_uri' => $this->redirectURI,
            )
        );

        // Add attributes
        $orcid = $data->{'orcid'};
        $state['Attributes']['orcid.path'] = array($orcid);
        if (!empty($data->{'name'})) {
            $state['Attributes']['orcid.name'] = array($data->{'name'});
        }

        // Get access token for retrieving public record
        $data = $this->_http('POST', $this->tokenEndpoint,
            array('Accept: application/json'),
            array(
                'client_id' => $this->clientId,
                'client_secret' => $this->clientSecret,
                'grant_type' => 'client_credentials',
                'scope' => '/read-public',
            )
        );

        $publicAccessToken = $data->{'access_token'};
        SimpleSAML_Logger::debug('[authorcid] finalStep: publicAccessToken=' 
            . $publicAccessToken);

        // Retrieve public record using access token
        $data = $this->_http('GET', $this->userInfoEndpoint . '/' . $orcid 
            . '/record/',
            array(
                'Accept: application/json',
                'Authorization: Bearer ' . $publicAccessToken,
            )
        );

        if (!empty($data->{'orcid-identifier'})) {
            $orcidIdentifier = $data->{'orcid-identifier'};
            if (!empty($orcidIdentifier->{'uri'})) {
                $state['Attributes']['orcid.uri'] = 
                    array($orcidIdentifier->{'uri'});
            }
            if (!empty($orcidIdentifier->{'host'})) {
                $state['Attributes']['orcid.host'] = 
                    array($orcidIdentifier->{'host'});
            }
        }

        if (!empty($data->{'person'}->{'name'})) {
            $nameData = $data->{'person'}->{'name'};
            if (!empty($nameData->{'given-names'}->{'value'})) {
                $state['Attributes']['orcid.given-names'] = 
                    array($nameData->{'given-names'}->{'value'});
            }
            if (!empty($nameData->{'family-name'}->{'value'})) {
                $state['Attributes']['orcid.family-name'] = 
                    array($nameData->{'family-name'}->{'value'});
            }
            if (!empty($nameData->{'credit-name'}->{'value'})) {
                $state['Attributes']['orcid.name'] = 
                    array($nameData->{'credit-name'}->{'value'});
            }
        }

        if (!empty($data->{'person'}->{'emails'}->{'email'})) {
            $emails = $data->{'person'}->{'emails'}->{'email'};
            foreach ($emails as $email) {
                if (!empty($email->{'primary'}) && !empty($email->{'email'})) {
                    $state['Attributes']['orcid.email'] = 
                        array($email->{'email'});
                    break;
                }
            }
        }
        SimpleSAML_Logger::debug('[authorcid] attributes=' . var_export($state['Attributes'], true));
    }

    private function _http($method, $url, $headers = array(), $data = null)
    {
        SimpleSAML_Logger::debug("[authorcid] http: method="
            . var_export($method, true) . ", url=" . var_export($url, true)
            . ", headers=" . var_export($headers, true)
            . ", data=" . var_export($data, true));
        $ch = curl_init($url);
        $opts = array(
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_SSL_VERIFYPEER => true,
        );
        if (strncmp($method, 'POST', 4) === 0 && !empty($data)) {
            $opts[CURLOPT_POSTFIELDS] = http_build_query($data);
        }
        curl_setopt_array($ch, $opts);

        // Send the request
        $response = curl_exec($ch);
        $httpResponseCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        if ($httpResponseCode !== 200) {
            SimpleSAML_Logger::error(
                "[authorcid] Failed to communicate with ORCID API:"
                . " HTTP response code: " . $httpResponseCode
                . ", error message: '" . curl_error($ch));
            throw new SimpleSAML_Error_Exception("Failed to communicate with ORCID API");
        }
        $data = json_decode($response);
        SimpleSAML_Logger::debug("[authorcid] http: data="
            . var_export($data, true));
        assert('json_last_error()===JSON_ERROR_NONE');
        // Check for error
        if (isset($data->{'error-desc'})) {
            SimpleSAML_Logger::error(
                "[authorcid] Error communicating with ORCID API:"
                    . var_export($data->{'error-desc'}, true));
            throw new Exception('Error communicating with ORCID API');
        }
        curl_close($ch);
        return $data;
    }

}
