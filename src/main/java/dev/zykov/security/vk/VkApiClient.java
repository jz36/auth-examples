package dev.zykov.security.vk;

import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Header;
import io.micronaut.http.annotation.QueryValue;
import io.micronaut.http.client.annotation.Client;
import org.reactivestreams.Publisher;

@Header(name = "User-Agent", value = "micronaut")
@Client("https://api.vk.com/method")
public interface VkApiClient {

    @Get("/users.get")
    Publisher<APIVkResponse> getUser(@QueryValue("access_token") String token, @QueryValue("v") String version, @QueryValue("fields") String fields);
}
