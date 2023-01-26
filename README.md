краткий план

* Приветствие
* О чем пойдет речь
* какие провайдеры будут сделаны
  * OpenID (google)
  * Yandex
* Процесс аутентификации
*Заключение

Добрый день!

Хочу познакомить вас с модулем аутентификации у Micronaut и заодно продемонстрировать, как настроить OAuth2.0 у нескольких провайдеров.

Для начала немного информации:

* Micronaut это современный JVM фреймворк, который в данный момент активно разрабатывается. Есть интересная [статья](https://habr.com/ru/post/418117/) про Micronaut.

* Какие провайдеры будут?
  * Google (OpenID)
  * Yandex
  * VK
* Что потребуется:
  * JDK 8+
  * Micronaut 3.7.0+
  * Ваш любимый редактор кода
  * Традиционные 15 минут свободного времени

## Конфигурация Micronaut

Для того чтобы собрать проект на Micronaut, можно использовать несколько инструментов:

* [Micronaut Launch](https://micronaut.io/launch) - сайт для сбора приложения, аналогичный Spring Initializr.
* CLI - command line interface от Micronaut.
* [SDKMAN!](https://sdkman.io/) - инструмент для параллельного менеджмента различных версий одного и того же SDK на одной машине (чаще всего UNIX)

Я буду использовать первый вариант, потому что мне он кажется самым удобным, особенно для первого запуска. Для этого заходим на сайт, и выбираем нужные зависимости. В данном случае нужно выбрать три зависимости:

* security;
* security-jwt;
* security-oauth2

Так же я использую Lombok, поскольку он позволяет уменьшить количество boilerplate кода. Так что можете добавить его в зависимости тоже.

Осталось выбрать версию Java и название проекта. Choose what you want.

В итоге должно получиться что-то вроде этого:

//todo insert image

Соответственно, остается только нажать кнопку __Generate Project__, и сайт предложит скачать его или выложить на GitHub. [Тут](https://github.com/jz36/auth-examples) репозиторий на эту статью с примерами кода.

## Реализация провайдеров

Для реализации аутентификации через сторонних провайдеров, необходимо для начала зарегестрировать у них приложение, которое и будет осуществлять механизм идентификации пользователя через внешнюю систему. Первым на очереди будет Google. Во-первых, это один из самых популярных сервисов, которые есть в мире, и скорее всего, у большинства ваших потенциальных пользователей есть Google аккаунт. Во-вторых, он реализует особую спецификацию OAuth2.0 под названием OpenID. Вот [хорошая статья](https://habr.com/ru/post/491116/), которая рассказывает об этих стандартах.

Так же давайте добавим некий контроллер, который позволит нам поприветствовать только что аутентифицированного пользователя:

```
@Controller
@Secured(SecurityRule.IS_AUTHENTICATED)
public class MainController {

    @Get
    public String greeting(Authentication authentication) {
        return "Hello, " + authentication.getName() + "!";
    }
}
```

Ну а мы приступаем к написанию аутентификации через Google.

### Google

Подробно расписывать получение клиента для аутентификации от Google я не вижу смысла. Как минимум, там относительно простой и интуитивно понятный интерфейс, к тому же в [интернете](https://developers.google.com/identity/openid-connect/openid-connect) уже есть подробное описание всех действий.

Стоит сказать что нужно внимательно отнестись к `callback url`. В процессе аутентификации провайдер сходит на ваш сервер, чтобы узнать, не являетесь ли вы злоумышленником. Сейчас нужно выставить `http://localhost:8080/oauth/callback/google`, но на проде советую так не делать.

//todo вставить изображение по гугл callback

После этого надо переместиться в `application.yml` и прописать `client-secret` и `client-id`, которые показываются после создания Credentials.

```
micronaut:
  security:
    oauth2:
      clients:
        google:
          client-id: your-client-id
          client-secret: your-client-secret
          openid:
            issuer: https://accounts.google.com
```

В принципе, самый простой вариант уже готов, и вы можете попробовать запустить наше приложение, а затем через браузер сходить на адрес `http://localhost:8080/oauth/login/google`

Таким образом можно увидеть стандартное окошко аутентификации от Google. Уверен, вы видели такое уже не раз. Теперь, если перейти по контроллеру, который мы объявили ранее, можно увидеть что-то вроде этого:

//todo вставить ответ от приложения

Другими примерами провайдеров, реализующих OpenID, могут выступать GitHub, Okta, KeyCloack.

### Yandex

Приступим к следующему провайдеру. Для начала так же необходимо клиента в системе Yandex. Для этого можно прочитать [инструкцию](https://yandex.ru/dev/id/doc/dg/oauth/tasks/register-client.html). На самом деле процесс схож с Google. Вводим имя приложения, его тип, добавляем необходимые для вашего приложения доступы, а так же определяем `callback url`. В результате должно получиться примерно так:

//todo вставить изображение из создания приложения по Yandex

Следующий шаг - заполнить необходимые параметры в `application.yml`. Так как Yandex реализует только OAuth2.0, а не OpenID, нужно указать больше параметров, чем в предыдущем разделе.

Минимально необходимой конфигурацией для OAuth2.0 приложения в Micronaut является:

* установить параметр endpoint'а для авторизации
* установить параметр endpoint'а для получения токена
* добавить `client-id` и `client-secret`, полученные ранее
* реализация `OauthAuthenticationMapper`

Таким образом получится следующая запись:

```
yandex:
  client-id: ${YANDEX_CLIENT_ID}
  client-secret: ${YANDEX_CLIENT_SECRET}
  authorization:
    url: https://oauth.yandex.ru/authorize
  token:
    url: https://oauth.yandex.ru/token
    auth-method: client-secret-post
  scopes: # этот параметр опционален, его указывать необязатльно
    - "login:birthday"
    - "login:email"
    - "login:info"
    - "login:avatar"
```

Вы могли заметить, что я появился новый еще один параметр, который до этого в статье не упоминался. Это `token.auth-method` - свойство, отвечающее за то, как будет аутентифицироваться наше приложение при выпуске токена в провайдере. Всего в Micronaut описано 7 способов, найти их можно [тут](https://micronaut-projects.github.io/micronaut-security/3.8.0/api/io/micronaut/security/oauth2/endpoint/AuthenticationMethod.html). Вообще, методы аутентификации подробно не описаны в стандарте [RFC 6749](https://tools.ietf.org/html/rfc6749#section-3.2.1), который как раз и описывает работу OAuth2.0. Однако, большинство провайдеров используют `client_secret_post`, в котором `client-id` и `client-secret` передаются в теле запроса, либо же используется `client-secret-basic`, где `client-id` и `client-secret` передаются в виде Basic аутентификации.

После того как были внесены необходимые параметры в `application.yml`, `Micronaut` требует, чтобы был реализован `OauthAuthenticationMapper`. Давайте к этому и приступим. Данная реализация должна иметь специальную аннотацию `@Named`, в которой значение должно совпадать с именем провайдера, указанного в конфигурационном файле.

Задача этого маппера сконвертировать `TokenResponse` в `Authentication`. В дальнейшем это приведет к тому, что будет происходить вызов некоторого API у провайдера для того, чтобы получить информацию о пользователе. Как только она будет получена, будут созданы `user details`, в соответствии с написанным кодом.

Чаще всего это используется для того, чтобы скомбинировать данные от провайдера с уже существующими записями в БД, либо же создать новую запись и дать пользователю права, аватарку, ник и т.д. В `Authentication` будут храниться следующие стандартные свойства - `username`, `roles` и `attributes`. Далее эти данные будут доступны из любого контроллера, который принимает `Autentication` в качестве параметра.

Для начала нужно создать класс, представляющий данные пользователя от провайдера:

```
@Introspected
@Data
@AllArgsConstructor
@NoArgsConstructor
public class YandexUser {

    private String id;

    @JsonProperty("first_name")
    private String firstName;

    @JsonProperty("last_name")
    private String lastName;

    @JsonProperty("display_name")
    private String nickName;

    @JsonProperty("default_email")
    private String email;
}
```

Потом нужно сделать `HttpClient` для выполнения запроса:

```
@Header(name = "User-Agent", value = "micronaut")
@Client("https://login.yandex.ru")
public interface YandexApiClient {

    @Get("/info")
    Flowable<YandexUser> getUser(@Header("Authorization") String authorization);
}
```

И финальный шаг - создание _user details mapper_, который при использовании клиента сможет выписать пользователю `Authentication`:

```
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
```

Проверить работу можно аналогично Google, просто сходить по адресу `http://localhost:8080/oauth/login/yandex`, и подтвердив свое желание аутентифицироваться через Yandex, увидеть приветствие.

## Процесс аутентификации

Настало время поговорить о том, как устроена аутентификация `Micronaut` внутри. Отчасти, мы уже немного затронули эту тему, когда создавали пользователя через `UserDetailsMapper`. Существует объект `Authentication`, который хранит данные о пользователе. Но что же происходит под капотом? Давайте разберем!

Для начала установим логгирование на уровень `trace`. Я использую `logback`, так что я просто добавлю такую строчку:

```
    <logger name="io.micronaut.security" level="trace"/>
```

Запустим и посмотрим, что появится в консоли:

```
DEBUG i.m.s.o.e.e.r.EndSessionEndpointResolver - Resolving the end session endpoint for provider [google]. Looking for a bean with the provider name qualifier
DEBUG i.m.s.o.e.e.r.EndSessionEndpointResolver - No EndSessionEndpoint bean found with a name qualifier of [google]
DEBUG i.m.s.o.e.e.r.EndSessionEndpointResolver - No EndSessionEndpoint can be resolved. The issuer for provider [google] does not match any of the providers supported by default
DEBUG i.m.s.o.routes.OauthRouteBuilder - Registering login route [GET: /oauth/login/vk] for oauth configuration [vk]
DEBUG i.m.s.o.routes.OauthRouteBuilder - Registering callback route [GET: /oauth/callback/vk] for oauth configuration [vk]
DEBUG i.m.s.o.routes.OauthRouteBuilder - Registering callback route [POST: /oauth/callback/vk] for oauth configuration [vk]
DEBUG i.m.s.o.routes.OauthRouteBuilder - Registering login route [GET: /oauth/login/yandex] for oauth configuration [yandex]
DEBUG i.m.s.o.routes.OauthRouteBuilder - Registering callback route [GET: /oauth/callback/yandex] for oauth configuration [yandex]
DEBUG i.m.s.o.routes.OauthRouteBuilder - Registering callback route [POST: /oauth/callback/yandex] for oauth configuration [yandex]
DEBUG i.m.s.o.routes.OauthRouteBuilder - Registering login route [GET: /oauth/login/google] for oauth configuration [google]
DEBUG i.m.s.o.routes.OauthRouteBuilder - Registering callback route [GET: /oauth/callback/google] for oauth configuration [google]
DEBUG i.m.s.o.routes.OauthRouteBuilder - Registering callback route [POST: /oauth/callback/google] for oauth configuration [google]
DEBUG i.m.s.o.routes.OauthRouteBuilder - Skipped registration of logout route. No openid clients found that support end session
```

Первое, что можно увидеть - `EndSessionEndpointResolver`. Этот бин отвечает, как не сложно догадаться, за определение контроллера, с помощью которого пользователь сможет завершить свою `OpenID` сессию. Тут же можно увидеть, что для Google такой endpoint найти не удалось, соответственно, он не будет зарегистрирован.

Следующий шаг - это `OauthRouteBuilder`. Он служит дя того, чтобы зарегистрировать контроллеры для всех провайдеров, которые будут настроены. Я добавил еще один провайдер, так что теперь будет создаваться 9 роутов, по одному для инициализации аутентификации и по два на `callback` для каждого провайдера.

Далее, для примера, я буду аутентифицироваться через Yandex.

```
DEBUG i.m.s.t.reader.HttpHeaderTokenReader - Looking for bearer token in Authorization header  #1
DEBUG i.m.s.t.reader.DefaultTokenResolver - Request GET, /, no token found.  #2
DEBUG i.m.security.rules.IpPatternsRule - One or more of the IP patterns matched the host address [127.0.0.1]. Continuing request processing.  #3
DEBUG i.m.s.rules.AbstractSecurityRule - None of the given roles [[isAnonymous()]] matched the required roles [[isAuthenticated()]]. Rejecting the request  #4
DEBUG i.m.security.filters.SecurityFilter - Unauthorized request GET /. The rule provider io.micronaut.security.rules.SecuredAnnotationRule rejected the request.  #5
DEBUG i.m.s.a.DefaultAuthorizationExceptionHandler - redirect uri: /  #6
```

Быстро посмотрим шаг за шагом, что происходит:

1. Проверка наличия `bearer` токена в заголовке `Authorization`
2. Сообщение вида "Какой тип запроса, путь, информация о токене"
3. В процессе конфигурации безопасности можно указать, с каких ip-адресов можно принимать запросы (по умолчанию, можно с любых). Здесь просто происходит проверка, что пришедший запрос пришел с разрешенного адреса
4. Происходит проверка, есть ли у пользователя, который пришел на `/`, нужная роль. В данном случае достаточно, просто, чтобы он был аутентифицирован. На данный момент это условие не выполняется.
   1. Вообще, `AbstractSecurityRule` выглядит очень логично. Если в объекте `Authentication` нет ничего, то `Micronaut` сообщает, что у данного пользователя есть только `isAnonymous()`. Потом, когда уже происходит вызов метода `compareRoles`, фреймворк просто считывает, что есть только роль анонимуса.
5. `SecurityFilter` сообщает текущую ситуацию, и какой провайдер правил "принял" такое решение.
6. Дальше просто сообщение о том, что происходит редирект на заранее определенный путь. Настраивается через конфигурацию.


