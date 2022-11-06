package dev.zykov.security.yandex;

import io.micronaut.core.annotation.Nullable;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.oauth2.endpoint.authorization.state.State;
import io.micronaut.security.oauth2.endpoint.token.response.OauthAuthenticationMapper;
import io.micronaut.security.oauth2.endpoint.token.response.TokenResponse;
import jakarta.inject.Named;
import jakarta.inject.Singleton;
import java.util.Collections;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Flux;

@Named("yandex") // Bean должен иметь данную аннотацию с тем же значением, которое было написано в файле конфигураций
@Singleton
@RequiredArgsConstructor
public class YandexUserDetailsMapper implements OauthAuthenticationMapper {
    private final YandexApiClient yandexApiClient;

    @Override
    public Publisher<AuthenticationResponse> createAuthenticationResponse(
        TokenResponse tokenResponse, @Nullable State state) {
        return Flux.from(yandexApiClient.getUser("OAuth " + tokenResponse.getAccessToken()))
            .map(user -> {
                List<String> roles = Collections.singletonList("ROLE_YANDEX");
                return AuthenticationResponse.success(user.getNickName(), roles);
            });
    }
}
