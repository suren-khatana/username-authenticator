package io.curity.identityserver.plugin.config;

import se.curity.identityserver.sdk.config.Configuration;
import se.curity.identityserver.sdk.service.Json;
import se.curity.identityserver.sdk.service.SessionManager;
import se.curity.identityserver.sdk.service.WebServiceClient;

@SuppressWarnings("InterfaceNeverImplemented")
public interface UsernameOnlyAuthenticatorPluginConfig extends Configuration
{
    SessionManager getSessionManager();
    WebServiceClient getWebServiceClient();
    Json getJson();
}
