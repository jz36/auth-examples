package dev.zykov.security.openid;

import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.oauth2.endpoint.authorization.state.State;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdAuthenticationMapper;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdClaims;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdTokenResponse;
import jakarta.inject.Named;
import jakarta.inject.Singleton;
import java.util.Collections;

@Named("google")
@Singleton
public class OpenIdUserDetailsMapper implements OpenIdAuthenticationMapper {

    @Override
    @NonNull
    public AuthenticationResponse createAuthenticationResponse(
        String providerName,
        OpenIdTokenResponse tokenResponse,
        OpenIdClaims openIdClaims,
        @Nullable State state
    ) {

        return AuthenticationResponse.success(
            openIdClaims.getName(),
            Collections.singletonList("ROLE_GOOGLE")
            );
    }
}

