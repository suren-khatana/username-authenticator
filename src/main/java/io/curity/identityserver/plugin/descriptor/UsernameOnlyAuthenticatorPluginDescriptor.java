package io.curity.identityserver.plugin.descriptor;

import io.curity.identityserver.plugin.authentication.UsernameOnlyAuthenticatorRequestHandler;
import io.curity.identityserver.plugin.config.UsernameOnlyAuthenticatorPluginConfig;
import se.curity.identityserver.sdk.authentication.AuthenticatorRequestHandler;
import se.curity.identityserver.sdk.plugin.descriptor.AuthenticatorPluginDescriptor;

import java.util.Map;

import static java.util.Collections.singletonMap;
import static java.util.Collections.unmodifiableMap;

public final class UsernameOnlyAuthenticatorPluginDescriptor implements AuthenticatorPluginDescriptor<UsernameOnlyAuthenticatorPluginConfig>
{
    @Override
    public String getPluginImplementationType()
    {
        return "username-only";
    }

    @Override
    public Class<? extends UsernameOnlyAuthenticatorPluginConfig> getConfigurationType()
    {
        return UsernameOnlyAuthenticatorPluginConfig.class;
    }

    @Override
    public Map<String, Class<? extends AuthenticatorRequestHandler<?>>> getAuthenticationRequestHandlerTypes()
    {
        return unmodifiableMap(singletonMap("index", UsernameOnlyAuthenticatorRequestHandler.class));
    }
}
