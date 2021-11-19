<?php

namespace MadMatt\Shibboleth;

use OneLogin\Saml2\Auth;
use OneLogin\Saml2\Error;
use OneLogin\Saml2\ValidationError;
use Psr\Log\LoggerInterface;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Core\Config\Config;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\ORM\ValidationException;
use SilverStripe\SAML\Control\SAMLController;
use SilverStripe\SAML\Helpers\SAMLHelper;
use SilverStripe\SAML\Services\SAMLConfiguration;
use SilverStripe\Security\Member;

/**
 * Class MadMatt\Shibboleth\ShibSAMLController
 * 
 * Overrides the SAMLController class to fix the acs() method, which operates differently for Shibboleth compared to 
 * Active Directory.
 */
class ShibSAMLController extends SAMLController
{
    private static $allowed_actions = [
        'acs',
        'metadata'
    ];

    /**
     * Assertion Consumer Service
     *
     * The user gets sent back here after authenticating with the IdP, off-site.
     * The earlier redirection to the IdP can be found in the SAMLAuthenticator::authenticate().
     *
     * After this handler completes, we end up with a rudimentary Member record (which will be created on-the-fly
     * if not existent), with the user already logged in.
     *
     * @return HTTPResponse
     * @throws Error
     * @throws ValidationException
     * @throws ValidationError
     */
    public function acs()
    {
        /** @var Auth $auth */
        $auth = Injector::inst()->get(SAMLHelper::class)->getSAMLAuth();
        $auth->processResponse();

        /** @var ShibSAMLConfiguration $samlConfig */
        $samlConfig = Injector::inst()->get('SAMLConfService');

        $error = $auth->getLastErrorReason();
        if (!empty($error)) {
            Injector::inst()->get(LoggerInterface::class)->error($error);
            Injector::inst()->get(LoggerInterface::class)->info(sprintf('SAML Response: %s', $auth->getLastResponseXML()));
            $session = $this->getRequest()->getSession();
            $session->set(
                'FormInfo.SAMLLoginForm_LoginForm.formError.message',
                "Authentication error: '{$error}'"
            );
            $session->set(
                'FormInfo.SAMLLoginForm_LoginForm.formError.type',
                'bad'
            );

            return $this->getRedirect();
        }

        if (!$auth->isAuthenticated()) {
            $session = $this->getRequest()->getSession();
            $session->set(
                'FormInfo.SAMLLoginForm_LoginForm.formError.message',
                _t('Member.ERRORWRONGCRED')
            );
            $session->set(
                'FormInfo.SAMLLoginForm_LoginForm.formError.type',
                'bad'
            );

            return $this->getRedirect();
        }
        
        // For Shibboleth IdPs, the 'unique' identifier field may not always be the provided NameID, and this depends on
        // the Shibboleth implementation. Here, we allow YML configuration to define how we attempt
        // See https://wiki.shibboleth.net/confluence/display/CONCEPT/NameIdentifiers for more info on the various types
        // Shibboleth supports
        $nameId = $samlConfig->getNameIDFromResponse($auth);

        $fieldToClaimMap = array_flip(Member::config()->get('claims_field_mappings', Config::EXCLUDE_EXTRA_SOURCES));
        $attributes = $auth->getAttributes();
        
        $uniqueIdentifierField = Config::inst()->get(SAMLConfiguration::class, 'shib_unique_identifier_field');
        
        if (!$uniqueIdentifierField) {
            $uniqueIdentifierField = 'GUID';
        }

        // Write a rudimentary member with basic fields on every login, so that we at least have something
        // if there is no further sync (e.g. via LDAP)
        $member = Member::get()->filter($uniqueIdentifierField, $nameId)->limit(1)->first();
        
        // If we allow fallback, check the provided NameID against the Email field (for sites that migrate from an old
        // system that stored the NameID in the Email field e.g. Apache's mod_shib module).
        // WARNING: This is *unsafe* unless you are certain that the NameID value will NEVER be re-used between users.
        if (!$member && (bool)Config::inst()->get(SAMLConfiguration::class, 'allow_unsafe_email_fallback')) {
            $member = Member::get()->filter('Email', $nameId)->limit(1)->first();
        }

        if (!($member && $member->exists())
            && Config::inst()->get(SAMLConfiguration::class, 'allow_insecure_email_linking')
            && isset($fieldToClaimMap['Email'])
        ) {
            // If there is no member found via GUID and we allow linking via email, search by email
            $member = Member::get()->filter('Email', $attributes[$fieldToClaimMap['Email']])->limit(1)->first();
            
            if (!($member && $member->exists())) {
                $member = Member::create();
            }

            $member->$uniqueIdentifierField = $nameId;
        } elseif (!($member && $member->exists())) {
            // If the member doesn't exist and we don't allow linking via email, then create a new member
            $member = Member::create();
            $member->$uniqueIdentifierField = $nameId;
        }

        // We always set/reset the NameID
        $member->$uniqueIdentifierField = $nameId;

        foreach ($member->config()->get('claims_field_mappings', Config::EXCLUDE_EXTRA_SOURCES) as $claim => $field) {
            if (!isset($attributes[$claim][0])) {
                Injector::inst()->get(LoggerInterface::class)->warning(
                    sprintf(
                        'Claim rule \'%s\' configured in claims_field_mappings, but wasn\'t passed through. Please check IdP claim rules defined in YML.',
                        $claim
                    )
                );

                continue;
            }

            $member->$field = $attributes[$claim][0];
        }

        $member->SAMLSessionIndex = $auth->getSessionIndex();

        $member->write();

        // This will trigger LDAP update through LDAPMemberExtension::memberLoggedIn.
        // The LDAP update will also write the Member record. We shouldn't write before
        // calling this, as any onAfterWrite hooks that attempt to update LDAP won't
        // have the Username field available yet for new Member records, and fail.
        // Both SAML and LDAP identify Members by the GUID field.
        $member->logIn();

        return $this->getRedirect();
    }
}
