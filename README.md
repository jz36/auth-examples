краткий план

* Приветствие
* О чем пойдет речь
* какие провайдеры будут сделаны
  * OpenID (google)
  * VK
  * Yandex
*Заключение

Добрый день!

Хочу познакомить вас с модулем аутентификации у Micronaut и заодно продемонстрировать, как настроить OAuth2.0 у нескольких провайдеров.

Для начала немного информации:

* Micronaut это современный JVM фреймворк, который в данный момент активно разрабатывается. Есть интересная [статья](https://habr.com/ru/post/418117/) про Micronaut. Несмотря на то, что актуальная версия Micronaut уже 3.8, статья своей актуальности не потеряла.
* Какие провайдеры будут?
  * Google (OpenID)
  * Yandex
  * VK
* Что потребуется:
  * JDK 8+
  * Micronaut 3.8.0
  * Ваш любимый редактор кода
  * Традиционные 15 минут свободного времени

## Конфигурация Micronaut

Для того, чтобы собрать проект на Micronaut, можно использовать несколько инструментов:

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

Вы могли заметить, что я появился новый еще один параметр, который до этого в статье не упоминался. Это `token.auth-method` - свойство, отвечающее за то, как будет аутентифицироваться наше приложение при выпуске токена в провайдере. Всего в Micronaut описано 7 способов, найти их можно [тут](https://micronaut-projects.github.io/micronaut-security/latest/api/io/micronaut/security/oauth2/endpoint/AuthenticationMethod.html). Вообще, методы аутентификации подробно не описаны в стандарте [RFC 6749](https://tools.ietf.org/html/rfc6749#section-3.2.1), который как раз и описывает работу OAuth2.0. Однако, большинство провайдеров используют `client_secret_post`, в котором `client-id` и `client-secret` передаются в теле запроса, либо же используется `client-secret-basic`, где `client-id` и `client-secret` передаются в виде Basic аутентификации.

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

Проверить работу можно аналогично Google, просто сходить по адресу `http://localhost:8080/oauth/login/yandex`, и подтвердив свое желание аутентифицироваться через Yandex, увидите приветствие


































