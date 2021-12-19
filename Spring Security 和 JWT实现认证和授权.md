### Spring Security 和 JWT实现认证和授权

​	在讲解Spring Security 和 JWT之前，我们先来了解一下**认证**和**授权**的基本概念。所谓认证(Authentication), 通俗地来说，就是搞清楚你是谁(who are you?); 而授权(Authorization), 就是你能干什么(what are you allowed to do?) 。 所有的安全框架，基本都是为了解决这两个问题的，Spring Security也不例外。

####  Spring Security的简介

- **过滤器链**

Spring Security是Spring家族推出一款用于认证和授权的安全框架。该框架采用职责链的设计模式，由多个过滤器组成过滤器链来完成认证和授权的功能。框架的大题结构如图1所示。

![image-20211211155202841](C:\Users\YUANCA2\AppData\Roaming\Typora\typora-user-images\image-20211211155202841.png)

<center size=5>图1- Spring Security 的过滤器链结构</center>

图1中红色框框中的过滤器链就是Spring Security的核心部分。对于每个客户端的请求，在到达Controller之前，除了应用本身定义的过滤器之外，还需要通过Spring Security过滤器链的处理。认证和授权的实现，都隐藏在这条过滤器链当中。下面是过滤器链中的部分过滤器以及它们处理请求的顺序。从每个过滤器的名字都能大概想到这些过滤器的作用。这里面需要重点关注的过滤器有：`Usernamepasswordauthenticationfilter`、`ExceptionTranslationFilter` 和 `FilterSecurityInterceptor`。`Usernamepasswordauthenticationfilter`主要通过用户名和密码来进行登录认证的；`ExceptionTranslationFilter` 是一个处理异常的过滤器，主要处理认证和授权中出现的异常；`FilterSecurityInterceptor`是过滤器链中最后一个过滤器，主要用于对客户端请求资源的权限进行判断。如果用户通过了这些过滤器并完成了认证和授权，那么就可以访问服务器中的资源啦。

```java
WebAsyncManagerIntegrationFilter
SecurityContextPersistenceFilter
HeaderWriterFilter    
CorsFilter    
CsrfFilter    
LogoutFilter    
...   
Usernamepasswordauthenticationfilter  
DefaultLoginPageGeneratingFilter    
DefaultLogoutPageGeneratingFilter    
BasicAuthenticationFilter    
...
RememberMeAuthenticationFilter    
AnonymousAuthenticationFilter
SessionManagementFilter
ExceptionTranslationFilter
FilterSecurityInterceptor     
```

- **Spring Security的基本概念**

前面大致了解了Spring Security过滤器链的整体面貌，现在让我们来认识一下Spring Security中一个基本的概念，以及怎么使用这些基本概念来完成用户的认证和授权。

**Authentication**: 在Spring Security中，`Authentication`用于表示一个被认证的用户信息。Authentication里面包含了用户信息(Principal)、密码(Credentials)以及所拥有的权限(Authorities)。

**SecurityContext**: Spring Security中的上下文对象，用于保存当前被认证的用户信息`Authentication`。

**SecurityContextHolder**: 从名字上也可以看出这个是用于保存`SecurityContext`的。默认的情况下，使用`ThreadLocal`来保存`SecurityContext`对象，因此在认证过后，可以在任意方法中通过`SecurityContext.getContext()`方法来获取当前`SecurityContext`。

`Authentication`、`SecurityContext`以及`SecurityContextHolder`这三者之间的关系如图2所示。

![image-20211219165718036](C:\Users\YUANCA2\AppData\Roaming\Typora\typora-user-images\image-20211219165718036.png)

```html
<center size=5>图2- Authentication、SecurityContext和SecurityContextHolder之间的关系</center>
```

在认证的时候，通常需要产生一个`Authentication`，然后按照`Authentication -> SecurityContext -> SecurityContextHolder`的顺序将认证的信息存放到安全上下文中。相反地，如果在认证后，想要获取当前用户信息，需要按照`SecurityContextHolder -> SecurityContext -> Authentication`的顺序获得，即`Authentication = SecurityContextHolder.getContext.getAuthentication()`。

**AuthenticationManager**: Spring Security默认的一个认证接口，定义了Spring Security认证的方法。通常情况下，需要在该方法中验证用户提交的信息，验证成功后将返回的`Authentication`对象保存到上下文中。当然啦，我们也可以不使用该接口而在别的地方将`Authentication`保存到当前上下文中。

```java 
public interface AuthenticationManager {
    Authentication authenticate(Authentication var1) throws AuthenticationException;
}
```

**ProviderManager**: 最常用的`AuthenticationManager`的实现。用于管理一个由`AuthenticationProvider`组成的链表。根据需要调用`AuthenticationProvider`提供的认证方式，如果全部都认证失败，则会抛出认证异常信息。

**AuthenticationProvider**： 每个`AuthenticationProvider`代表了一种特定的认证方式。比如常用的`DAOAuthenticationProvider`会根据开发的需要加载`username`和`password`来进行认证。

**DAOAuthenticationProvider**:  调用`userDetailsService.loadUserByUsername()`方法得到用户信息，以完成认证的过程。

**UserDetailsService**: 要完成用户的认证，必不可少的一部分就是验证用户的`username`和`password`是否正确。而在真实的系统中，用户的信息通常保存在数据库中（Spring Security也支持保存在配置文件和内存中）。加载用户信息的逻辑，通常需要实现Spring Security的`UserDetailsService`接口，并在对应的方法中返回一个`UserDetails`以供后续的认证和授权。

**UserDetails**: `userDetailsService.loadUserByUsername()`放回的类型，`Authentication`中`Principal`通常也是一个`UserDetails`。

**PassowrdEncoder**: 用户密码不可能明文保存，Spring Security提供了一些`passwordEncoder`用于用户密码。官方推荐使用的是`BCryptPasswordEncoder`。

#### JWT (Json Web Token)

JWT是一种基于Json的开放标准（[RFC 7519](https://tools.ietf.org/html/rfc7519)），用于在通信双方之间安全地表示声明（claims）。

- **Session 和 Token**

​        首先，HTTP是一种无状态的协议，服务器端想要知道当前是哪个用户在访问，传统的方式是使用session。当用户登录成功之后，在服务器端保存一份用户的信息，并对应生成一个sessionId返回给客户端，下次客户端再次访问服务端的时候，会以cookie的形式携带该sessionId，这样服务端就可以知道是谁在访问了。

​        基于session的方式可以很容易实现认证和授权，当时当用户越来越多的时候，服务器端需要保存的用户信息也会随之增加。更加头疼的是，当应用需要扩展的时候，例如增加机器， 新的机器里面因没有某用户的信息而识别不了该用户，因此往往需要Redis之类的来实现分布式session的功能。除此之外，基于session的认证有可能会引起CSRF攻击。因为sessionId是通过cookie的方式来传输的，某些钓鱼网站可以通过诱骗等，盗取用户的cookie从而发起CSRF攻击。

​        基于Token的方式是用户第一次登陆的时候，服务器端生成一个可以唯一标识该用户的token字符串，并返回给客户端。下次客户端访问的时候在header上携带该token，服务端即可识别到该用户。与session不同的是，token的信息是保存在客户端的，而session的用户信息则是保存在服务器端。服务器端需要做的是解析和验证token中的信息，因此也有人说，token的方式是使用时间换空间的思想。

- JWT

JWT是一种很适合在分布式环境的token认证方式，它由三个部分组成: 头部(Header)、负载(Payload)、签名(Signature)。每部分经过base64编码后，用`.`来进行链接即构成了JWT字符串。例如：`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.UoyOF2YXMFZvQVFn6MNsynp7NiCXweMH4imJfv187zM`

Header一般是一个固定的结构，由签名算法(alg)和类型(typ)组成，通常为如下JSON数据。

```js
{
    "alg": "HS256",
    "typ": "JWT"    
}
```

Header经过base64 编码后成为了JWT的第一部分: `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9`。

Payload用于存放真实需要传递的数据，通常有官方规定的字段和开发者自定义的字段。需要注意的是，payload中的数据只是进行base64的编码，并没有加密效果，因此不要在payload中存放密码之类的敏感信息。payload的一个简单例子如下：

```json
{
    "sub": "1234567890", // 官方字段
    "name": "Caps Yuan" //用户自定义字段
}
```

对payload进行base64编码即可构成了JWT的第二部分： `eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0`。

Signature是对header和payload进行的签名，主要用来防止数据被篡改。签名需要用到header和payload的base64编码后的结果以及header中的签名算法和服务器端指定的一个密钥(secret)。 签名的大致过程如下面所示：

```js
signature = HMACSHA256(base64encode(header) + "." + base64encode(payload), 'handsomeboy')
```

签名后的结果为： `UoyOF2YXMFZvQVFn6MNsynp7NiCXweMH4imJfv187zM`。

将上面三个字符串用`.`链接起来即构成了JWT。



#### Spring Security 和 JWT 实现前后端分离的认证和授权

- **引入相关Spring Security 和 JWT 依赖**

```xml
<!--  由于篇幅原因，只列出Spring Security 和 JWT的依赖，完整的依赖可以参考底部源代码链接  -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt</artifactId>
    <version>0.9.1</version>
</dependency>
```

- **Spring Security相关配置**

```java
@Configuration
@EnableWebSecurity
@EnableConfigurationProperties(value = {SecurityProperties.class, JwtTokenProperties.class})
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private SecurityProperties securityProperties;

    private JwtAuthenticationTokenFilter jwtAuthenticationTokenFilter;


    public SecurityConfig(SecurityProperties securityProperties, JwtAuthenticationTokenFilter jwtAuthenticationTokenFilter) {
        this.securityProperties = securityProperties;
        this.jwtAuthenticationTokenFilter = jwtAuthenticationTokenFilter;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http.cors();

        http.csrf().disable();

        http.authorizeRequests()
                .antMatchers(securityProperties.getIgnoreUrls().toArray(new String[0])).permitAll()
                .anyRequest().authenticated()
                .and().exceptionHandling()
                    .authenticationEntryPoint(new MyEntryPoint())
                    .accessDeniedHandler(new MyAccessDeniedHandler());

        http.addFilterBefore(jwtAuthenticationTokenFilter, UsernamePasswordAuthenticationFilter.class);

        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}

```

- **JWT 工具类实现**

```java
@Component
public class JwtUtil {

    private JwtTokenProperties jwtTokenProperties;

    public JwtUtil(JwtTokenProperties jwtTokenProperties) {
        this.jwtTokenProperties = jwtTokenProperties;
    }

    public String generateToken(String username) {
        Date now = new Date();
        Date expireData = new Date(now.getTime() + 1000 * jwtTokenProperties.getExpire());

        return Jwts.builder()
                .setHeaderParam("typ", "JWT")
                .setSubject(username)
                .setIssuedAt(now)
                .setExpiration(expireData)
                .signWith(SignatureAlgorithm.HS512, jwtTokenProperties.getSecret())
                .compact();
    }

    public Claims getClaimByToken(String jwt) {
        try {
            return Jwts.parser()
                    .setSigningKey(jwtTokenProperties.getSecret())
                    .parseClaimsJws(jwt)
                    .getBody();
        } catch (Exception exception) {
            return null;
        }
    }

    public boolean isTokenExpired(Claims claims) {
        return claims.getExpiration().before(new Date());
    }
}

```

- **用户信息的查询**

```java
@Override
public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    UserPo userPo = userRepository.findByUsername(username);
    if (userPo == null) {
        throw new UsernameNotFoundException("Username Not Found.");
    }
    List<UserRolePo> userRolePos = userRoleRepository.findByUsername(username);
    List<String> roles = userRolePos.stream().map(UserRolePo::getName).collect(Collectors.toList());

    return SecurityUser.builder()
        .username(userPo.getUsername())
        .password(userPo.getPassword())
        .authorities(AuthorityUtils.commaSeparatedStringToAuthorityList(String.join(",", roles)))
        .build();
}
```



- **认证的实现**

上文中表示，用于认证的过滤器是`UsernamePasswordAuthenticationFilter`。因此，我们需要实现该过滤器或者在该过滤器之前实现我们的认证功能。这里选择后者，定义一个新的过滤器，然后将自定义的过滤器加到`UsernamePasswordAuthenticationFilter`之前。

```java
@Slf4j
@Component
public class JwtAuthenticationTokenFilter extends OncePerRequestFilter {

    private UserDetailsServiceImpl userDetailsService;

    private JwtTokenProperties jwtTokenProperties;

    private JwtUtil jwtUtil;

    public JwtAuthenticationTokenFilter(UserDetailsServiceImpl userDetailsService, JwtTokenProperties jwtTokenProperties, JwtUtil jwtUtil) {
        this.userDetailsService = userDetailsService;
        this.jwtTokenProperties = jwtTokenProperties;
        this.jwtUtil = jwtUtil;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        Claims claims = jwtUtil.getClaimByToken(request.getHeader(jwtTokenProperties.getHeader()));
        if (claims != null && !jwtUtil.isTokenExpired(claims)) {
            String username = claims.getSubject();
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);
            if (userDetails != null) {
                log.info("userDetails: " + userDetails);
                Authentication authentication = new UsernamePasswordAuthenticationToken(userDetails.getUsername(), userDetails.getPassword(), userDetails.getAuthorities());
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }
        filterChain.doFilter(request, response);
    }
}
```

在配置类中添加该过滤器：

```java
http.addFilterBefore(jwtAuthenticationTokenFilter, UsernamePasswordAuthenticationFilter.class);
```



- **授权的实现**

与登录类似，首先需要使用`@EnableGlobalMethodSecurity(prePostEnabled = true)`开启授权控制，然后在`UserDetailsService.loadUserByUsername()`中将该用户的权限加到`UserDetails`中，在需要权限控制的API中加入`@PreAuthorize("hasRole('ADMIN')")`即可限制只有`ROLE_ADMIN`角色的用户才可以访问该API。

```java
@GetMapping("/{username}")
@PreAuthorize("hasRole('ADMIN')")
public CommonResult<UserDTO> findByUsername(@PathVariable("username") String username) {
    return userService.findByUsername(username);
}
```



- **完整代码： https://github.com/sylinder/spring-security-jwt.git**