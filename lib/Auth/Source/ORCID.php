<?php

namespace SimpleSAML\Module\authorcid\Auth\Process;

use SimpleSAML\Auth\Source;
use SimpleSAML\Auth\State;
use SimpleSAML\Logger;
use SimpleSAML\Module;
use SimpleSAML\Utilities;

/**
 * Authenticate using ORCID.
 *
 * This SimpleSAMLphp authentication source can be configured to use either
 * the Public or Member ORCID API to allow users to sign in with their ORCID
 * account. Accessing the ORCID API requires a set of client credentials
 * consisting of a Client ID and a Client Secret.
 *
 * You can configure credentials for the Public API from a personal ORCID
 * account. You can then use this authentication source to retrieve a user's
 * authenticated ORCID iD and a JSON-formatted version of their public ORCID
 * record. Member API clients have access to additional scopes to read-limited
 * information (or write) to an ORCID record.
 *
 * Example authentication source configuration:
 *
 *     'orcid' => [
 *         'authorcid:ORCID',
 *         'clientId' => 'APP-XXXXXXXXXXXXXXXX',
 *         'clientSecret' => 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx',
 *     ],
 *
 * @author Nicolas Liampotis <nliam@grnet.gr>
 */
class ORCID extends Source
{
    /*
     * The string used to identify the init state
     */
    public const STAGE_INIT = 'authorcid:init';

    /*
     * The key of the AuthId field in the state
     */
    public const AUTHID = 'authorcid:AuthId';

    /*
     * The key of the authZ code in the state
     */
    public const CODE = 'authorcid:code';

    /*
     * The ORCID Client redirect URI
     * @var string
     */
    private $redirectUri;

    /*
     * The ORCID client application ID
     * @var string
     */
    private $clientId;

    /*
     * The ORCID client application secret
     * @var string
     */
    private $clientSecret;

    /*
     * URL of ORCID's OAuth 2.0 Authorization endpoint.
     * Needs to match the ORCID environment:
     * - 'https://orcid.org/oauth/authorize'         (Production)
     * - 'https://sandbox.orcid.org/oauth/authorize' (Sandbox)
     * @var string
     */
    private $authorizeEndpoint = 'https://orcid.org/oauth/authorize';

    /*
     * URL of ORCID's OAuth 2.0 Token endpoint.
     * Needs to match the ORCID environment:
     * - 'https://orcid.org/oauth/token'             (Production)
     * - 'https://sandbox.orcid.org/oauth/token'     (Sandbox)
     * @var string
     */
    private $tokenEndpoint = 'https://orcid.org/oauth/token';

    /*
     * Base URL of ORCID's Record API: [userInfoEndpoint]/[orcidId]/record
     * Needs to match the ORCID API version and environment:
     * - 'https://pub.orcid.org/v3.0'                Public API (Production)
     * - 'https://api.orcid.org/v3.0'                Member API (Production)
     * - 'https://pub.sandbox.orcid.org/v3.0'        Public API (Sandbox)
     * - 'https://api.sandbox.orcid.org/v3.0'        Member API (Sandbox)
     */
    private $userInfoEndpoint = 'https://pub.orcid.org/v3.0';

    /*
     * The permission of access requested by the ORCID client application.
     * For example:
     * - '/authenticate': Allows a Public or Member client application to
     *   obtain the record holder's 16-character ORCID iD and read public
     *   information on that ORCID record
     * - '/read-limited': Allows a Member client application to obtain the
     *   record holder's ORCID iD and read public and limited access
     *   information on that ORCID record
     * @var string
     */
    private $scope = '/authenticate';


    /**
     * Constructor for this authentication source.
     *
     * @param array $info  Information about this authentication source.
     * @param array $config  Configuration.
     */
    public function __construct($info, $config)
    {
        assert('is_array($info)');
        assert('is_array($config)');

        // Call the parent constructor first, as required by the interface
        parent::__construct($info, $config);

        $this->redirectUri = Module::getModuleUrl('authorcid/redirect.php');

        if (!array_key_exists('clientId', $config)) {
            throw new Exception('ORCID authentication source is not properly configured: Missing clientId');
        }
        $this->clientId = $config['clientId'];

        if (!array_key_exists('clientSecret', $config)) {
            throw new Exception('ORCID authentication source is not properly configured: Missing clientSecret');
        }
        $this->clientSecret = $config['clientSecret'];

        if (array_key_exists('authorizeEndpoint', $config)) {
            if (!is_string($config['authorizeEndpoint'])) {
                Logger::error(
                    "ORCID authentication source is not properly configured: 'authorizeEndpoint' not a string literal"
                );
                throw new Exception(
                    "ORCID authentication source is not properly configured: 'authorizeEndpoint' not a string literal"
                );
            }
            $this->authorizeEndpoint = $config['authorizeEndpoint'];
        }

        if (array_key_exists('tokenEndpoint', $config)) {
            if (!is_string($config['tokenEndpoint'])) {
                Logger::error(
                    "ORCID authentication source is not properly configured: 'tokenEndpoint' not a string literal"
                );
                throw new Exception(
                    "ORCID authentication source is not properly configured: 'tokenEndpoint' not a string literal"
                );
            }
            $this->tokenEndpoint = $config['tokenEndpoint'];
        }

        if (array_key_exists('userInfoEndpoint', $config)) {
            if (!is_string($config['userInfoEndpoint'])) {
                Logger::error(
                    "ORCID authentication source is not properly configured: 'userInfoEndpoint' not a string literal"
                );
                throw new Exception(
                    "ORCID authentication source is not properly configured: 'userInfoEndpoint' not a string literal"
                );
            }
            $this->userInfoEndpoint = $config['userInfoEndpoint'];
        }

        if (array_key_exists('scope', $config)) {
            if (!is_string($config['scope'])) {
                Logger::error("ORCID authentication source is not properly configured: 'scope' not a string literal");
                throw new Exception(
                    "ORCID authentication source is not properly configured: 'scope' not a string literal"
                );
            }
            $this->scope = $config['scope'];
        }
    }


    /**
     * Authenticate using ORCID credentials
     * Documentation at https://members.orcid.org/orcid-sign-in
     *
     * @param array &$state  Information about the current authentication.
     */
    public function authenticate(&$state)
    {
        assert('is_array($state)');

        // We are going to need the authId in order to retrieve this
        // authentication source later
        $state[self::AUTHID] = $this->authId;

        $stateId = State::saveState($state, self::STAGE_INIT, true);
        $authorizeUri = $this->authorizeEndpoint
            . '?client_id=' . $this->clientId
            . '&response_type=code'
            . '&scope=' . $this->scope
            . '&show_login=true'
            . '&state=' . $stateId
            . '&redirect_uri=' . $this->redirectUri;

        // Redirect to ORCID authorize endpoint
        Utilities::redirect($authorizeUri);
    }


    public function finalStep(&$state)
    {
        assert('is_array($state)');

        $code = $state[self::CODE];
        Logger::debug('[authorcid] finalStep: code=' . $code);

        // Exchange ORCID authZ code with access token
        $data = $this->http(
            'POST',
            $this->tokenEndpoint,
            ['Accept: application/json'],
            [
                'client_id' => $this->clientId,
                'client_secret' => $this->clientSecret,
                'grant_type' => 'authorization_code',
                'code' => $code,
                'redirect_uri' => $this->redirectUri,
            ]
        );

        // Add attributes
        $orcid = $data->{'orcid'};
        $state['Attributes']['orcid.path'] = [$orcid];
        if (!empty($data->{'name'})) {
            $state['Attributes']['orcid.name'] = [$data->{'name'}];
        }

        $accessToken = null;
        if (!empty($data->{'access_token'})) {
            $accessToken = $data->{'access_token'};
        }
        Logger::debug('[authorcid] finalStep: accessToken=' . $accessToken);

        // Retrieve ORCID record using access token
        $data = $this->http(
            'GET',
            $this->userInfoEndpoint . '/' . $orcid . '/record',
            [
                'Accept: application/json',
                'Authorization: Bearer ' . $accessToken,
            ]
        );

        if (!empty($data->{'orcid-identifier'})) {
            $orcidIdentifier = $data->{'orcid-identifier'};
            if (!empty($orcidIdentifier->{'uri'})) {
                $state['Attributes']['orcid.uri'] = [$orcidIdentifier->{'uri'}];
            }
            if (!empty($orcidIdentifier->{'host'})) {
                $state['Attributes']['orcid.host'] = [$orcidIdentifier->{'host'}];
            }
        }

        if (!empty($data->{'person'}->{'name'})) {
            $nameData = $data->{'person'}->{'name'};
            if (!empty($nameData->{'given-names'}->{'value'})) {
                $state['Attributes']['orcid.given-names'] = [$nameData->{'given-names'}->{'value'}];
            }
            if (!empty($nameData->{'family-name'}->{'value'})) {
                $state['Attributes']['orcid.family-name'] = [$nameData->{'family-name'}->{'value'}];
            }
            if (!empty($nameData->{'credit-name'}->{'value'})) {
                $state['Attributes']['orcid.name'] = [$nameData->{'credit-name'}->{'value'}];
            }
        }

        // The list of email addresses returned from the UserInfo endpoint
        $orcidEmails = [];
        // The list of verified email addresses returned from the UserInfo
        // endpoint
        $verifiedOrcidEmails = [];
        // The primary email address returned from the UserInfo endpoint.
        $primaryOrcidEmail = null;
        if (!empty($data->{'person'}->{'emails'}->{'email'})) {
            $emails = $data->{'person'}->{'emails'}->{'email'};
            foreach ($emails as $email) {
                if (!empty($email->{'email'})) {
                    $orcidEmails[] = $email->{'email'};
                    if (!empty($email->{'verified'})) {
                        $verifiedOrcidEmails[] = $email->{'email'};
                    }
                    if (!empty($email->{'primary'})) {
                        $primaryOrcidEmail = $email->{'email'};
                    }
                }
            }
        }
        Logger::debug('[authorcid] orcidEmails=' . var_export($orcidEmails, true));
        Logger::debug('[authorcid] verifiedOrcidEmails=' . var_export($verifiedOrcidEmails, true));
        Logger::debug('[authorcid] primaryOrcidEmail=' . var_export($primaryOrcidEmail, true));
        // If no email address in the response is marked as primary then we
        // assume that the first returned address is the primary one
        if (!empty($orcidEmails)) {
            if (!empty($primaryOrcidEmail)) {
                $state['Attributes']['orcid.email'] = [$primaryOrcidEmail];
            } else {
                $state['Attributes']['orcid.email'] = [array_values($orcidEmails)[0]];
            }
        }
        if (!empty($verifiedOrcidEmails)) {
            $state['Attributes']['orcid.verified-emails'] = $verifiedOrcidEmails;
        }

        Logger::debug('[authorcid] attributes=' . var_export($state['Attributes'], true));
    }

    private function http($method, $url, $headers = [], $data = null)
    {
        Logger::debug(
            "[authorcid] http: method=" . var_export($method, true)
            . ", url=" . var_export($url, true)
            . ", headers=" . var_export($headers, true)
            . ", data=" . var_export($data, true)
        );
        $ch = curl_init($url);
        $opts = [
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_SSL_VERIFYPEER => true,
        ];
        if (strncmp($method, 'POST', 4) === 0 && !empty($data)) {
            $opts[CURLOPT_POSTFIELDS] = http_build_query($data);
        }
        curl_setopt_array($ch, $opts);

        // Send the request
        $response = curl_exec($ch);
        // Check for HTTP error
        if (curl_errno($ch)) {
            $errorMsg = curl_error($ch);
        }
        curl_close($ch);

        if (isset($errorMsg)) {
            Logger::error("[authorcid] Failed to communicate with ORCID API:" . " HTTP Error message: '" . $errorMsg);
            throw new Exception("Failed to communicate with ORCID API:" . " HTTP Error message: '" . $errorMsg);
        }
        $data = json_decode($response);
        Logger::debug("[authorcid] http: data=" . var_export($data, true));
        assert('json_last_error()===JSON_ERROR_NONE');
        // Check for ORCID API error
        if (isset($data->{'error-desc'})) {
            Logger::error("[authorcid] Error communicating with ORCID API:" . var_export($data->{'error-desc'}, true));
            throw new Exception("Error communicating with ORCID API");
        }

        return $data;
    }
}
