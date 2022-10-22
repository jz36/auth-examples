package dev.zykov;

import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.rules.SecurityRule;

@Controller
@Secured(SecurityRule.IS_AUTHENTICATED)
public class MainController {

    @Get
    public String greeting(Authentication authentication) {
        return "Hello, " + authentication.getName() + "!";
    }
}
