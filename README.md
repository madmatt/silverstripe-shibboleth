# silverstripe-shibboleth

Extends the [silverstripe-saml](https://github.com/silverstripe/silverstripe-saml) module for Silverstripe 4 to provide [Shibboleth](https://wiki.shibboleth.net/confluence/display/IDP30/Home) specific bindings, and allow the silverstripe-saml module to be used with a Shibboleth-backed identity provider (IdP).

See the [silverstripe-saml developer documentation](https://github.com/silverstripe/silverstripe-saml/tree/master/docs/en) for the majority of information on how to configure this module. Additional features specific to Shibboleth are noted below.

## Custom configuration

### Implementing your own custom SAMLConfiguration

This module defines a sub-class of `SAMLConfiguration` for the `SAMLConfService`. If you want to extend it, make sure you extend `ShibSAMLConfiguration`.

### Specifying a custom attribute as the NameID

Some Shibboleth implementations will always present a transient NameID, meaning that it can't be used to identify the same user every time. If this is the case, check with the IdP vendor first - the best option is to have the NameID returned in a persistent format (see [Shibboleth Name Identifiers documentation](https://wiki.shibboleth.net/confluence/display/CONCEPT/NameIdentifiers)).

However, if changing this isn't possible, you can optionally specify an attribute that is returned in the SAML response to use instead as the 'NameID' (e.g. the unique value used to lookup a user).

Do this by adding the following to your YML configuration:

```yaml
# The below will use the eduPersonPrincipalName attribute to determine the NameID
# See a full list of oid -> 'friendly name' mappings here: https://incommon.org/community-practices-and-standards/object-identifier-registrations/
MadMatt\Shibboleth\SAMLConfiguration:
  nameid_override_attribute: "urn:oid:1.3.6.1.4.1.5923.1.1.1.6"
```

### Specifying a custom SilverStripe field to compare the NameID to

By default, the Shibboleth module does not change how the NameID is compared to how the base module works (e.g. it will store the NameID in the `GUID` column, and lookup existing members using that field). However, you can override this by providing a value for the `shib_unique_identifier_field` config variable.

This may be useful in a situation where you are migrating from the old SilverStripe `auth_external` module, using the Apache `mod_shib` module (which populates `$_SERVER['REMOTE_USER']` by default).

```yaml
MadMatt\Shibboleth\SAMLConfiguration:
  shib_unique_identifier_field: Email
```