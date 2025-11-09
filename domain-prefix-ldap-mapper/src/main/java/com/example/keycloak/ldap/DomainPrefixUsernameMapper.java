package com.example.keycloak.ldap;

import org.keycloak.component.ComponentModel;
import org.keycloak.models.LDAPConstants;
import org.keycloak.models.UserModel;
import org.keycloak.storage.ldap.LDAPStorageProvider;
import org.keycloak.storage.ldap.idm.model.LDAPObject;
import org.keycloak.storage.ldap.idm.query.internal.LDAPQuery;
import org.keycloak.storage.ldap.mappers.AbstractLDAPStorageMapper;
import org.keycloak.storage.ldap.mappers.AbstractLDAPStorageMapperFactory;

/**
 * Mapper LDAP, który importuje username w formacie: DOMENA\sAMAccountName
 */
public class DomainPrefixUsernameMapper extends AbstractLDAPStorageMapper {

    private static final String DOMAIN_PREFIX_CONFIG = "domain.prefix";

    public DomainPrefixUsernameMapper(ComponentModel mapperModel, LDAPStorageProvider ldapProvider) {
        super(mapperModel, ldapProvider);
    }

    @Override
    public void onImportUserFromLDAP(LDAPObject ldapUser, UserModel user, boolean isCreate) {
        String sAMAccountName = ldapUser.getAttributeAsString(LDAPConstants.SAM_ACCOUNT_NAME);
        
        if (sAMAccountName != null && !sAMAccountName.isEmpty()) {
            String domainPrefix = mapperModel.getConfig().getFirst(DOMAIN_PREFIX_CONFIG);
            
            if (domainPrefix != null && !domainPrefix.isEmpty()) {
                String username = domainPrefix + "\\" + sAMAccountName;
                user.setUsername(username.toLowerCase());
            } else {
                user.setUsername(sAMAccountName.toLowerCase());
            }
        }
    }

    @Override
    public void onRegisterUserToLDAP(LDAPObject ldapUser, UserModel localUser, ComponentModel ldapModel) {
        // Przy rejestracji usuwamy prefix domeny
        String username = localUser.getUsername();
        String domainPrefix = mapperModel.getConfig().getFirst(DOMAIN_PREFIX_CONFIG);
        
        if (domainPrefix != null && username.startsWith(domainPrefix + "\\")) {
            String sAMAccountName = username.substring((domainPrefix + "\\").length());
            ldapUser.setSingleAttribute(LDAPConstants.SAM_ACCOUNT_NAME, sAMAccountName);
        } else {
            ldapUser.setSingleAttribute(LDAPConstants.SAM_ACCOUNT_NAME, username);
        }
    }

    @Override
    public UserModel proxy(LDAPObject ldapUser, UserModel delegate, ComponentModel ldapModel) {
        return delegate;
    }

    @Override
    public void beforeLDAPQuery(LDAPQuery query) {
        // Nie modyfikujemy zapytania
    }

    public static class Factory extends AbstractLDAPStorageMapperFactory {

        public static final String PROVIDER_ID = "domain-prefix-username-ldap-mapper";

        @Override
        public String getHelpText() {
            return "Mapuje username z LDAP w formacie: DOMENA\\sAMAccountName";
        }

        @Override
        public String getId() {
            return PROVIDER_ID;
        }

        @Override
        protected AbstractLDAPStorageMapper createMapper(ComponentModel mapperModel, LDAPStorageProvider federationProvider) {
            return new DomainPrefixUsernameMapper(mapperModel, federationProvider);
        }

        @Override
        public List<ProviderConfigProperty> getConfigProperties() {
            List<ProviderConfigProperty> configProperties = new ArrayList<>();
            
            ProviderConfigProperty domainPrefix = new ProviderConfigProperty();
            domainPrefix.setName(DOMAIN_PREFIX_CONFIG);
            domainPrefix.setLabel("Domain Prefix");
            domainPrefix.setHelpText("Prefix domeny do dodania przed username (np. CONTOSO, EXAMPLE)");
            domainPrefix.setType(ProviderConfigProperty.STRING_TYPE);
            domainPrefix.setDefaultValue("");
            configProperties.add(domainPrefix);
            
            return configProperties;
        }
    }
}