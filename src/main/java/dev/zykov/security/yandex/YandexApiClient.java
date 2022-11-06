package dev.zykov.security.yandex;

import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Header;
import io.micronaut.http.client.annotation.Client;
import org.reactivestreams.Publisher;

@Header(name = "User-Agent", value = "micronaut")
@Client("https://login.yandex.ru")
public interface YandexApiClient {

    @Get("/info")
    Publisher<YandexUser> getUser(@Header("Authorization") String authorization);
}
