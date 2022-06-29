package io.curity.identityserver.plugin.authentication;

import io.curity.identityserver.plugin.config.UsernameOnlyAuthenticatorPluginConfig;
import io.fusionauth.jwt.Signer;
import io.fusionauth.jwt.domain.JWT;
import io.fusionauth.jwt.rsa.RSASigner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import se.curity.identityserver.sdk.attribute.*;
import se.curity.identityserver.sdk.authentication.AuthenticationResult;
import se.curity.identityserver.sdk.authentication.AuthenticatorRequestHandler;
import se.curity.identityserver.sdk.http.HttpRequest;
import se.curity.identityserver.sdk.http.HttpResponse;
import se.curity.identityserver.sdk.http.HttpStatus;
import se.curity.identityserver.sdk.service.ExceptionFactory;
import se.curity.identityserver.sdk.service.Json;
import se.curity.identityserver.sdk.service.WebServiceClient;
import se.curity.identityserver.sdk.service.authentication.AuthenticatorInformationProvider;
import se.curity.identityserver.sdk.web.Request;
import se.curity.identityserver.sdk.web.Response;


import java.io.UnsupportedEncodingException;

import java.net.URLEncoder;

import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.*;

import static se.curity.identityserver.sdk.web.Response.ResponseModelScope.NOT_FAILURE;
import static se.curity.identityserver.sdk.web.ResponseModel.templateResponseModel;

public final class UsernameOnlyAuthenticatorRequestHandler implements AuthenticatorRequestHandler<RequestModel> {
    private static final Logger _logger = LoggerFactory.getLogger(UsernameOnlyAuthenticatorRequestHandler.class);

    private final UsernameOnlyAuthenticatorPluginConfig _config;
    private final AuthenticatorInformationProvider _authInfoProvider;
    private final ExceptionFactory _exceptionFactory;

    private final WebServiceClient _webServiceClient;
    private final Json _json;


    public UsernameOnlyAuthenticatorRequestHandler(UsernameOnlyAuthenticatorPluginConfig config, ExceptionFactory exceptionFactory, AuthenticatorInformationProvider authInfoProvider) {
        _config = config;
        _exceptionFactory = exceptionFactory;
        _authInfoProvider = authInfoProvider;
        _webServiceClient = config.getWebServiceClient();
        _json = config.getJson();
    }

    @Override
    public Optional<AuthenticationResult> get(RequestModel requestModel, Response response) {
        _logger.info("GET request received for authentication authentication");

        return Optional.empty();
    }

    @Override
    public Optional<AuthenticationResult> post(RequestModel requestModel, Response response) {
        String username = requestModel.getPostRequestModel().getUserName();

        // call client credentials with JWT assertion
        String jws = generateJWS();

        HashMap<String, String> requestBody = new HashMap<>();
        requestBody.put("client_id", "jwt-assertion-test-client");
        requestBody.put("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
        requestBody.put("client_assertion", jws);
        requestBody.put("grant_type", "client_credentials");

        String data = getDataString(requestBody);

        _logger.info("******************, request Body data =  {} ", data);

        HttpResponse httpResponse = _webServiceClient.request().contentType("application/x-www-form-urlencoded").body(HttpRequest.fromByteArray(data.getBytes())).post().response();

        // check response to get token
        _logger.info("###########################################################################################");
        _logger.info(String.valueOf(httpResponse.statusCode()));
        _logger.info(httpResponse.body(HttpResponse.asString()));
        _logger.info("###########################################################################################");
        _logger.info("###########################################################################################");

        return Optional.of(new AuthenticationResult(AuthenticationAttributes.of(SubjectAttributes.of(username, Attributes.of(Attribute.of("username", username))), ContextAttributes.of(Attributes.of(Attribute.of("iat", new Date().getTime()))))));

    }


    private String getDataString(HashMap<String, String> params) {
        StringBuilder result = new StringBuilder();
        boolean first = true;
        for (Map.Entry<String, String> entry : params.entrySet()) {
            if (first) first = false;
            else result.append("&");
            try {
                result.append(URLEncoder.encode(entry.getKey(), "UTF-8"));

                result.append("=");
                result.append(URLEncoder.encode(entry.getValue(), "UTF-8"));
            } catch (UnsupportedEncodingException e) {
                throw new RuntimeException(e);
            }
        }
        return result.toString();
    }


    public String generateJWS() {
        // Create a signer using the custom RSA private key.
        Signer signer = null;
        // Private key is hard-coded in the code for demo purposes , should NEVER be stored in the code.
        signer = RSASigner.newSHA256Signer("-----BEGIN RSA PRIVATE KEY-----\n" + "MIIEpQIBAAKCAQEAvWh/NvbMd2nB1XlAEjb4RLT91h0jyPPYZpWpfRgNlVtkJpvP\n" + "OMlnQqz0orjNSBMW8A3eXvh5qm1vHaaQ0K+mezTexiGh6gkBL1qA65jvw7n91CfB\n" + "5T09zjyfOzajWeGU1NBSaB+ZmUhOB7oVrcGg8/M3/G6uJZAQbpIrvRTwUo6MjASM\n" + "mjEkWGbNMA4tWPy/oUvUXc5k8VrwE1QE48DZAptuFfdx1KIJdC6AK8+YbPoMRG6G\n" + "oXyvxKOyEwvoOoHjlcXYVQFESDElSP037cPrqWSgdNQdPXFWL4NX7DCT/+ehMa33\n" + "S6xXUqFYSwR+wQ/BkdCEoQLy78hp0oXf2H6/swIDAQABAoIBAE7qvSZ/ig2vCM4T\n" + "KPjt4l9uMd0GYySVRPLpJKc0YGR8oavce2ijsdx8B6nM6es/2OzIOoDDcp3p3sQx\n" + "5GCu7uSi0LcoyDek7NN4GAMRw8R/OB0vO4ByFdBaPdYEG+eVL9fDvLIZiHvvPmPF\n" + "ysaMyK0cB5Wr3+9SqSYIzSSJFuCuQIHMVgab5xzINtUIFobv4l4RWEoToHnJAme2\n" + "8WesBY1d74mwGuRNiIwC2cCIItpN05csJ+Zp+hxwrxe0qYKWdOCb2LDSo3YTkAHB\n" + "YjOGOh23auE8zKK8uOlnaAhnlr1bn23i/91qOXX7ZV1GOt0RI5KNhnyjIwOiqcs5\n" + "uxRbxnECgYEA5fYDhrrz9/CS7a3Dd0xA62OjiJEoM+KGyVpg5x8+q4oupS1oJsrv\n" + "cs9SBQXbykYuyAWM+EGPg/Fkj7HAiMPqkgEz8bF3TA6j1SBnjYaz7Gpf/W+N1oec\n" + "A7fiU49vzJfJ9fsbwQyhMRViMzpNdOiHXJNEb2ejt6W6ZfnGIcnHRIUCgYEA0tr1\n" + "1J/c8t9sov1S3yjuN9Mx681v/2S6uU6HNzTKp8kOhIw8X4c/JxVB1FmXmKcA1m7/\n" + "Q/x+cd97s+FEwudptC3UUlXOSyuN9/Z4alLiCwWgmPbW9LgIegeSwNMvOiaPltYF\n" + "YSmEZn7AsqTKiaME2qM44JvaWbH91rciRfDzpNcCgYEAuJLffbJsw2MK605/By/j\n" + "I4vT5Hdt50c4nEC4aom/iXvduKJbaFeWHXaeBH4RTadLQSyDW3dzs5l694LaYGuv\n" + "yQTCJookkJ1njlb2BrhJjcZLyWVSWRB7ftiHBj6oo3Rpm8+zFR4H+xeIvEldhipl\n" + "Cz8AvNJYq7yPge4aw1/rWukCgYEAmpMCHHmFVFcOIP5svkQXPr2In0Dfle6WJDq5\n" + "TXNaDV6LUggsSiuv1Er1E2MKi1ICfzCn2YNEft5CpT/DVM6o4vml6SYWMW0gimMZ\n" + "K3jPVR0u+nQaaRRwwmTC5LDsskiKgx0qnGv/L9REF7JO+E+Vw2Jc0+vtSkv9tmZS\n" + "rctSEckCgYEAjCHhVTkOjUPcObEiCWqodJG0o7s3MR3qUV+dN9Qe7j+GIrXfWPtM\n" + "3ykAMg8LR22CUM7k/HNXRV3gfsxnWZ0oU1z0/YVV/HHBL2NN/ctrSIEHytRjoRLr\n" + "a7iCFy26alR8rs7z2in84VfeUr6mseoSC1oKYDpuIJ41P2ysAltUw1Y=\n" + "-----END RSA PRIVATE KEY-----");

        // Create a new JWT as per the specification https://datatracker.ietf.org/doc/html/rfc7523#section-3
        JWT jwt = new JWT()
                .setIssuer("jwt-assertion-test-client")
                .setIssuedAt(ZonedDateTime.now(ZoneOffset.UTC))
                .setSubject("jwt-assertion-test-client")
                .setExpiration(ZonedDateTime.now(ZoneOffset.UTC).plusMinutes(10)).setUniqueId(UUID.randomUUID().toString())
                .setNotBefore(ZonedDateTime.now(ZoneOffset.UTC)).setAudience("https://login-external.curity.local/external/~")
                .addClaim("my-claim","my-value");

        // Sign and encode the JWT
        String jws = JWT.getEncoder().encode(jwt, signer);
        _logger.info("************************************* JWT client assertion = {}", jws);
        return jws;
    }

    @Override
    public RequestModel preProcess(Request request, Response response) {
        // set the template and model for responses on the NOT_FAILURE scope
        response.setResponseModel(templateResponseModel(Collections.emptyMap(), "authenticate/get"), NOT_FAILURE);
        // on request validation failure, we should use the same template as for NOT_FAILURE
        response.setResponseModel(templateResponseModel(Collections.emptyMap(), "authenticate/get"), HttpStatus.BAD_REQUEST);

        return new RequestModel(request);

    }
}
