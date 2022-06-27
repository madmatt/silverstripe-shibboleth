<?php

namespace Madmatt\Shibboleth;

use OneLogin\Saml2\Auth;
use SilverStripe\SAML\Services\SAMLConfiguration;

/**
 * Class Madmatt\Shibboleth\ShibSAMLConfiguration
 *
 * Provides additional configuration functionality for Shibboleth-backed identity providers (IdP).
 */
class ShibSAMLConfiguration extends SAMLConfiguration
{
    /**
     * @var string Allows for the ability to override the default NameID resolution value to use a SAML attribute
     * instead. See README.md for usage instructions.
     */
    private static $nameid_override_attribute = '';

    /**
     * @var string Allows for the ability to define a unique field to find the {@link Member} by. See README.md for
     * usage instructions.
     */
    private static $shib_unique_identifier_field = '';

    /**
     * @param Auth $auth The processed AuthN response (must be valid)
     * @return string NameID (or equivalent attribute that should be treated as the NameID) of the authenticated user
     * @throws \Exception
     */
    public function getNameIDFromResponse(Auth $auth)
    {
        if (!$auth->isAuthenticated()) {
            throw new \Exception('Provided SAMLResponse is not valid, can\'t retrieve NameID');
        }

        $attribute = SAMLConfiguration::config()->get('nameid_override_attribute');

        // If an override attribute is not specified, then default to the NameID returned by the IdP (default)
        if (!$attribute) {
            return $auth->getNameId();
        }

        if (!is_string($attribute)) {
            throw new \Exception('Provided config value nameid_override_attribute must be a string');
        }

        // If an override attribute is specified, get all attributes and ensure the required attribute is present
        $attributes = $auth->getAttributes();

        if (isset($attributes[$attribute]) && isset($attributes[$attribute][0])) {
            return $attributes[$attribute][0];
        } else {
            throw new \Exception(sprintf('Required attribute %s not provided in SAML response', $attribute));
        }
    }
}