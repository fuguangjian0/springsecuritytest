## SpringSecurity 入门

> 把security流程说出来,就是面试的加分项

![](https://p9-juejin.byteimg.com/tos-cn-i-k3u1fbpfcp/9c80c66df56e44128a57638a6d477cd8~tplv-k3u1fbpfcp-zoom-in-crop-mark:4536:0:0:0.awebp?)

### 简介

SpringSecurity 解决的是认证和授权问题

`认证`:确认当前访问系统的用户是不是本系统用户,同时确认具体是哪个用户

`授权`:认证后判断这个用户有哪些操作的使用权限

SpringSecurity 作为作为安全框架的核心功能是认证和授权

### 引入

依赖

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>
```

登入接口

localhost:8080/login

![image-20230701202000301](https://imgfff-1313020458.cos.ap-shanghai.myqcloud.com/images/image-20230701202000301.png)

登出接口

localhost:8080/logout

![image-20230701201914490](https://imgfff-1313020458.cos.ap-shanghai.myqcloud.com/images/image-20230701201914490.png)

### 登录校验流程

1. 前端使用用户名密码访问后端登录接口
2. 后端把接收的用户名密码和数据库里的用户名密码校验
3. 如果正确,使用用户名或用户id,生成jwt
4. 把jwt给前端
5. 登录后访问其他请求需要在请求头携带token
6. 后端获取token进行解析,获得userId
7. 根据userId获取用户相关信息,确定这个用户有没有访问这个资源的权限
8. 如果有权限,则访问目标资源,返回给前端响应信息

### 完整流程

![image-20230701203455365](https://imgfff-1313020458.cos.ap-shanghai.myqcloud.com/images/image-20230701203455365.png)

由一系列过滤器组成的过滤器链实现

UsernamePasswordAuthenticationFilter:  负责`认证` ,处理填写用户名密码后登录请求过滤器

ExceptionTranslationFilter: 处理过滤器链抛出的特定异常

FilterSecurityInterceptor: 负责`校验` 的过滤器

### 断点调试过滤器链

更改springboot容器启动类,加一个断点

![image-20230701204629302](https://imgfff-1313020458.cos.ap-shanghai.myqcloud.com/images/image-20230701204629302.png)

对表达式求值,即可得到过滤器链

![image-20230701204703402](https://imgfff-1313020458.cos.ap-shanghai.myqcloud.com/images/image-20230701204703402.png)

### 认证流程详解

![image-20230703164622978](https://imgfff-1313020458.cos.ap-shanghai.myqcloud.com/images/image-20230703164622978.png)

概念:

Authentication接口:实现类,表示当前访问系统的用户,封装了用户相关信息

AuthenticationManager接口:定义认证Authentication的方法

UserDetailService接口:加载用户特定数据的核心数据,里面定义了用户名查询用户信息的方法

UserDetails接口:提供核心用户信息,通过UserDetailsService根据用户名获取处理用户信息封装成UserDetails对象返回,然后将这些信息封装到Authentication对象中

### 解决问题

我们需要修改UserDetailsService

![image-20230701210833914](https://imgfff-1313020458.cos.ap-shanghai.myqcloud.com/images/image-20230701210833914.png)



![image-20230701211223817](https://imgfff-1313020458.cos.ap-shanghai.myqcloud.com/images/image-20230701211223817.png)

### 思路分析

登录:

1.自定义登录接口

​		调用ProviderManager方法进行认证 如果认证通过生成Jwt

​		把用户信息存入redis

2.自定义UserDetailService

​		在这个实现列中去查询数据库

校验:

定义Jwt认证过滤器

​	获取token

​	解析token获取userId

​	从redis获取用户信息

​	存入SecurityContextHolder

### 准备工作

导入实体类  返回结果类  工具类  配置类  



### 数据库校验用户

导入mybatisplus和mysql依赖

```xml
        <dependency>
            <groupId>com.mysql</groupId>
            <artifactId>mysql-connector-j</artifactId>
            <scope>runtime</scope>
        </dependency>
        <dependency>
            <groupId>com.baomidou</groupId>
            <artifactId>mybatis-plus-boot-starter</artifactId>
            <version>3.4.2</version>
        </dependency>
```

配置数据库信息

```yml
spring:
  datasource:
    driver-class-name: com.mysql.cj.jdbc.Driver
    url: jdbc:mysql://localhost:3306/reggie?serverTimezone=Asia/Shanghai&useUnicode=true&characterEncoding=utf-8&zeroDateTimeBehavior=convertToNull&useSSL=false&allowPublicKeyRetrieval=true
    username: root
    password: root
```

编写UserDetailServiceImpl实现UserDetailsService接口来重写loadUserByUsername来打通security和数据库

```java
@Service
public class UserDetailServiceImpl implements UserDetailsService {
    @Mapper
    UserMapper userMapper;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        //查询用户信息
        LambdaQueryWrapper<User> wrapper = new LambdaQueryWrapper<>();
        wrapper.eq(true, User::getUserName, username);
        User user = userMapper.selectOne(wrapper);
        if (user == null) {
            throw new UsernameNotFoundException("用户名或密码错误");
        }
        //TODO 查询对应的权限信息

         //这里返回的LoginUser类需要重新定义
        return new LoginUser(user);
       
    }
}
```

LoginUser类需要重新定义,把数据库的用户名和密码返回给过滤器链

```java
@Data
@NoArgsConstructor
@AllArgsConstructor
public class LoginUser implements UserDetails {

    private User user;


    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return null;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUserName();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
```

### 密码加密存储

在SecurityConfig中添加passwordEncoder加密方法,并注入到容器

```java
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    //创建BCryptPasswordEncoder注入容器
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
}    
```

测试其中两个方法 - 加密 - 校验

```java
@Test
    void contextLoads() {
        BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
        //加密方法
        String encode = bCryptPasswordEncoder.encode("123456");
        log.info(encode);
//        $2a$10$ez5U9ia1ldX1CJCGjKZPfOQYu2ygl7G1t6TaIbV5olotknZUaF7.q
        //校验方法
        boolean matches = bCryptPasswordEncoder.
                matches("123456",
                        "$2a$10$ez5U9ia1ldX1CJCGjKZPfOQYu2ygl7G1t6TaIbV5olotknZUaF7.q");
        log.info("匹配是否成功:" + matches);
    }
```

### jwt工具类加密

引入工具类

```java
package com.example.utils;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

/**
 * JWT工具类
 */
public class JwtUtil {

    //有效期为
    public static final Long JWT_TTL = 60 * 60 *1000L;// 60 * 60 *1000  一个小时
    //设置秘钥明文
    public static final String JWT_KEY = "sangeng";

    public static String getUUID(){
        String token = UUID.randomUUID().toString().replaceAll("-", "");
        return token;
    }
    
    /**
     * 生成jtw
     * @param subject token中要存放的数据（json格式）
     * @return
     */
    public static String createJWT(String subject) {
        JwtBuilder builder = getJwtBuilder(subject, null, getUUID());// 设置过期时间
        return builder.compact();
    }

    /**
     * 生成jtw
     * @param subject token中要存放的数据（json格式）
     * @param ttlMillis token超时时间
     * @return
     */
    public static String createJWT(String subject, Long ttlMillis) {
        JwtBuilder builder = getJwtBuilder(subject, ttlMillis, getUUID());// 设置过期时间
        return builder.compact();
    }

    private static JwtBuilder getJwtBuilder(String subject, Long ttlMillis, String uuid) {
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;
        SecretKey secretKey = generalKey();
        long nowMillis = System.currentTimeMillis();
        Date now = new Date(nowMillis);
        if(ttlMillis==null){
            ttlMillis=JwtUtil.JWT_TTL;
        }
        long expMillis = nowMillis + ttlMillis;
        Date expDate = new Date(expMillis);
        return Jwts.builder()
                .setId(uuid)              //唯一的ID
                .setSubject(subject)   // 主题  可以是JSON数据
                .setIssuer("sg")     // 签发者
                .setIssuedAt(now)      // 签发时间
                .signWith(signatureAlgorithm, secretKey) //使用HS256对称加密算法签名, 第二个参数为秘钥
                .setExpiration(expDate);
    }

    /**
     * 创建token
     * @param id
     * @param subject
     * @param ttlMillis
     * @return
     */
    public static String createJWT(String id, String subject, Long ttlMillis) {
        JwtBuilder builder = getJwtBuilder(subject, ttlMillis, id);// 设置过期时间
        return builder.compact();
    }



    /**
     * 生成加密后的秘钥 secretKey
     * @return
     */
    public static SecretKey generalKey() {
        byte[] encodedKey = Base64.getDecoder().decode(JwtUtil.JWT_KEY);
        SecretKey key = new SecretKeySpec(encodedKey, 0, encodedKey.length, "AES");
        return key;
    }
    
    /**
     * 解析
     *
     * @param jwt
     * @return
     * @throws Exception
     */
    public static Claims parseJWT(String jwt) throws Exception {
        SecretKey secretKey = generalKey();
        return Jwts.parser()
                .setSigningKey(secretKey)
                .parseClaimsJws(jwt)
                .getBody();
    }


}
```



由于jdk17缺少一个类包,自行导入依赖

```xml
<dependency>
    <groupId>javax.xml.bind</groupId>
    <artifactId>jaxb-api</artifactId>
    <version>2.3.1</version>
</dependency>
```



在方法内进行测试

```java
    public static void main(String[] args) throws Exception {
        String jwt = createJWT("123456");
        System.out.println(jwt);
        Claims claims = parseJWT("eyJhbGciOiJIUzI1NiJ9.eyJqdGkiOiJkNmM1MTZhYjA1OTc0OTI4OTkwNzFmY2YyOWM1ZGU0NSIsInN1YiI6IjEyMzQ1NiIsImlzcyI6InNnIiwiaWF0IjoxNjg4MjYyMTY5LCJleHAiOjE2ODgyNjU3Njl9.XwaPFja2oJz8PkykBILBVK2sh_32eeLkS8b-AFxwfP4");
        String subject = claims.getSubject();
        System.out.println(subject);
        //123456
    }
```



### 登录接口思路,实现

自定义登录接口

LoginController.java

```java
@RestController
public class LoginController {

    @Resource
    LoginService service;

    @PostMapping("/user/login")
    public ResponseResult login(@RequestBody User user) {
        return service.login(user);
    }

}
```



然后这个接口放行,不需要登录也能访问这个接口

SecurityConfig.java

```java
@Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .sessionManagement()
            	.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeRequests()
                .antMatchers("/user/login").anonymous()
                .anyRequest().authenticated();
    }
```



①接口中用到AuthenticationManager的authenticate方法进行用户认证,在securityConfig中配置把AuthenticationManager注入容器

SecurityConfig.java

```java
	@Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
```



②认证成功生成jwt,放入响应返回,让用户通过jwt识别具体哪个用户

③把用户信息存入redis,把userId用户id作为key

LoginServiceImpl.java

```java
@Override
    public ResponseResult login(User user) {
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(user.getUserName(), user.getPassword());
        Authentication authenticate = authenticationManager.authenticate(authenticationToken);
        if (Objects.isNull(authenticate)) throw new RuntimeException("登录失败");
        LoginUser loginUser = (LoginUser) authenticate.getPrincipal();
        Long id = loginUser.getUser().getId();
        String userId = id.toString();
        //生成jwt
        String jwt = JwtUtil.createJWT(userId);
        HashMap<String, String> map = new HashMap<>();
        map.put("token", jwt);
        redisCache.setCacheObject("login:"+userId, loginUser);

        return new ResponseResult(200, "登录成功", map);
    }
```

postman返回结果

![image-20230702163230752](https://imgfff-1313020458.cos.ap-shanghai.myqcloud.com/images/image-20230702163230752.png)

### token认证过滤器

定义jwt认证过滤器

​		获取token

​		解析token获取其中userId

​		从redis获取用户信息

​		存入SecurityContextHolder

JwtAuthenticationTokenFilter.java

```java
@Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        //获取token
        String token = request.getHeader("token");
        if (!StringUtils.hasText(token)) {
            //放行
            filterChain.doFilter(request, response);
            return;
        }
        //解析token
        String userId;
        try {
            Claims claims = JwtUtil.parseJWT(token);
            userId = claims.getSubject();
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("token非法");
        }
        //从redis获取用户信息
        String redisKey = "login:" + userId;
        LoginUser loginUser = redisCache.getCacheObject(redisKey);
        if (Objects.isNull(loginUser)) throw new RuntimeException("用户未登录");
        //存入SecurityContextHolder
        //TODO  获取权限信息封装到Authentication
        UsernamePasswordAuthenticationToken authenticationToken
                = new UsernamePasswordAuthenticationToken(loginUser, null, null);
        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
        //放行
        filterChain.doFilter(request,response);
    }
```

把过滤器放到UsernamePasswordAuthenticationFilter之前(before)

```java
@Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                			.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeRequests()
                .antMatchers("/user/login").anonymous()
                .anyRequest().authenticated();
        //添加过滤器 Filter
        http
                .addFilterBefore(jwtAuthenticationTokenFilter, UsernamePasswordAuthenticationFilter.class);
    }
```

### 注销

LoginController.java

```java
@RequestMapping("/user/logout")
    public ResponseResult logout() {
        return service.logout();
    }
```



LoginServiceImpl.java

```java
@Override
    public ResponseResult logout() {
        //获取securityContextHolder中的用户id
        UsernamePasswordAuthenticationToken authenticationToken = (UsernamePasswordAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();
        LoginUser loginUser = (LoginUser) authenticationToken.getPrincipal();
        Long userId = loginUser.getUser().getId();
        //删除redis中的值
        redisCache.deleteObject("login:"+userId);
        return new ResponseResult(200, "注销成功");
    }
```

### 认证配置详解

认证配置在SecurityConfig的configure方法

```java
@Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeRequests()
                .antMatchers("/user/login").anonymous()
            //.permitAll();
                .anyRequest().authenticated();
        http
                .addFilterBefore(jwtAuthenticationTokenFilter, UsernamePasswordAuthenticationFilter.class);
    }
```

anonymous 匿名访问,登录可以不访问,未登录可以访问

permitAll 随便访问,无论登录|未登录都可以进行访问

authenticated 只有认证之后才能访问

### 授权概念

不同的用户使用不同的功能,充值VIP|会员或管理员

### 添加权限(不通数据库)

基于注解来管理权限

```java
@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {
}
```

HelloController.java

```java
	@RequestMapping("/hello")
    @PreAuthorize("hasAuthority('test')")//写死test
    public String hello() {
        return "hello";
    }
```

loadUserByUsername中查询权限信息

UserDetailsServiceImpl.java

```java
@Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        LambdaQueryWrapper<User> wrapper = new LambdaQueryWrapper<>();
        wrapper.eq(User::getUserName, username);
        User user = userMapper.selectOne(wrapper);
        if (Objects.isNull(user)) {
            throw new RuntimeException("用户名或密码错误");
        }
        //查询权限信息
        ArrayList<String> list = new ArrayList<>(Arrays.asList("test", "admin"));
        return new LoginUser(user, list);
    }
```

获取权限信息封装到Authentication

JwtAuthenticationTokenFilter.java

```java
@Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        //获取token
        String token = request.getHeader("token");
        if (!StringUtils.hasText(token)) {
            //放行
            filterChain.doFilter(request, response);
            return;
        }
        //解析token
        String userId;
        try {
            Claims claims = JwtUtil.parseJWT(token);
            userId = claims.getSubject();
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("token非法");
        }
        //从redis获取用户信息
        String redisKey = "login:" + userId;
        LoginUser loginUser = redisCache.getCacheObject(redisKey);
        if (Objects.isNull(loginUser)) throw new RuntimeException("用户未登录");
        //存入SecurityContextHolder
        //获取权限信息封装到Authentication
        UsernamePasswordAuthenticationToken authenticationToken
                = new UsernamePasswordAuthenticationToken(loginUser, null, loginUser.getAuthorities());//LoginUser中重写getAuthorities方法
        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
        //放行
        filterChain.doFilter(request,response);
    }
```

LoginUser中重写getAuthorities方法

```java
@Data
@NoArgsConstructor
@AllArgsConstructor
public class LoginUser implements UserDetails {
    private User user;

    private List<String> permissions;

    public LoginUser(User user, List<String> permissions) {
        this.user = user;
        this.permissions = permissions;
    }

    @JSONField(serialize = false) //这里规定此处不能序列化存入SecurityContextHolder,为了安全
    private List<SimpleGrantedAuthority> authorities;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {

        //把permissions中string类型的权限信息封装成实现类SimpleGrantedAuthority对象
//        authorities = new ArrayList<>();
//        for (String permission : permissions) {
//            SimpleGrantedAuthority authority = new SimpleGrantedAuthority(permission);
//            authorities.add(authority);
//        }
        if (authorities != null) return authorities;

        authorities = permissions.stream()
                .map(SimpleGrantedAuthority::new)
                .toList();
        return authorities;
    }
    .......
}
```



### 设计权限模型 

 RBAC 权限模型

一个用户可以有多个角色,一个角色可以有多个权限

![image-20230702183831864](https://imgfff-1313020458.cos.ap-shanghai.myqcloud.com/images/image-20230702183831864.png)



### 导入数据库文件

根据 userId 查找权限

```sql
SELECT DISTINCT
	m.perms 
FROM
	sys_user_role ur
	LEFT JOIN `sys_role` r ON ur.`role_id` = r.`id`
	LEFT JOIN `sys_role_menu` rm ON ur.role_id = rm.role_id
	LEFT JOIN `sys_menu` m ON m.`id` = rm.menu_id 
WHERE
	user_id = 2 
	AND r.`status` = 0
```

### 添加权限(通数据库)

mapper接口

```java
public interface MenuMapper extends BaseMapper<Menu> {
    // 多表联查,mp无能为力
    List<String> selectPermsByUserId(Long userId);
}
```

UserDetailsServiceImpl.java

```java
@Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        LambdaQueryWrapper<User> wrapper = new LambdaQueryWrapper<>();
        wrapper.eq(User::getUserName, username);
        User user = userMapper.selectOne(wrapper);
        if (Objects.isNull(user)) {
            throw new RuntimeException("用户名或密码错误");
        }
        //查询权限信息
//        ArrayList<String> list = new ArrayList<>(Arrays.asList("test", "admin"));
        List<String> list = menuMapper.selectPermsByUserId(user.getId());
        return new LoginUser(user, list);
    }
```



hellocontroller.java

```java
@RequestMapping("/hello")
//    @PreAuthorize("hasAuthority('test')")//写死test
    @PreAuthorize("hasAuthority('system:dept:list')")
    public String hello() {
        return "hello";
    }
```

menumapper.xml

```xml
<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE mapper PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN" "http://mybatis.org/dtd/mybatis-3-mapper.dtd" >
<mapper namespace="com.example.mapper.MenuMapper">

    <select id="selectPermsByUserId" resultType="java.lang.String" parameterType="java.lang.Long">
        SELECT
            DISTINCT m.`perms`
        FROM
            sys_user_role ur
                LEFT JOIN `sys_role` r ON ur.`role_id` = r.`id`
                LEFT JOIN `sys_role_menu` rm ON ur.`role_id` = rm.`role_id`
                LEFT JOIN `sys_menu` m ON m.`id` = rm.`menu_id`
        WHERE
            user_id = #{userId}
          AND r.`status` = 0
          AND m.`status` = 0
    </select>
</mapper>
```

### 自定义错误处理

认证失败或授权失败青空返回json数据给前端,由前端统一处理,一切来源于springsecurity的异常处理机制,异常封装成AuthenticationException判断认证失败还是授权失败

`认证`错误封装成AuthenticationException后调用AuthenticationEntryPoint对象方法进行异常处理

`授权`错误封装成AccessDenieException调用AccessDeniedHandler对象方法进行异常处理

handler包下

AccessDeniedHandlerImpl.java

```java
@Component
public class AccessDeniedHandlerImpl implements AccessDeniedHandler {
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
        ResponseResult result = new ResponseResult(HttpStatus.FORBIDDEN.value(), "您的权限不足");//403
        String json = JSONObject.toJSONString(result);
        WebUtils.renderString(response, json);
    }
}
```

AuthenticationEntryPointImpl.java

```java
@Component
public class AuthenticationEntryPointImpl implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        ResponseResult result = new ResponseResult(HttpStatus.UNAUTHORIZED.value(), "用户认证失败请查询登录");//401
        String json = JSONObject.toJSONString(result);
        WebUtils.renderString(response, json);
    }
}
```

在SecurityConfig中configure使用

```java
@Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeRequests()
                .antMatchers("/user/login").anonymous()
                .anyRequest().authenticated();
        http    //添加过滤器
                .addFilterBefore(jwtAuthenticationTokenFilter, UsernamePasswordAuthenticationFilter.class);
        http    //添加异常处理
                .exceptionHandling()
                .authenticationEntryPoint(authenticationEntryPoint)
                .accessDeniedHandler(accessDeniedHandler);
    }
```

![image-20230702212253607](https://imgfff-1313020458.cos.ap-shanghai.myqcloud.com/images/image-20230702212253607.png)

![image-20230702212108320](https://imgfff-1313020458.cos.ap-shanghai.myqcloud.com/images/image-20230702212108320.png)

### 开启跨域

跨域是`浏览器`的同源保护机制,现在前后端分离部署在不同服务器上

新建一个配置类

```java
@Configuration
public class CorsConfig implements WebMvcConfigurer {

    @Override
    public void addCorsMappings(CorsRegistry registry) {
      // 设置允许跨域的路径
        registry.addMapping("/**")
                // 设置允许跨域请求的域名
                .allowedOriginPatterns("*")
                // 是否允许cookie
                .allowCredentials(true)
                // 设置允许的请求方式
                .allowedMethods("GET", "POST", "DELETE", "PUT")
                // 设置允许的header属性
                .allowedHeaders("*")
                // 跨域允许时间
                .maxAge(3600);
    }
}
```



SecurityConfig

```java
@Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeRequests()
                .antMatchers("/user/login").anonymous()
                .anyRequest().authenticated();
        http    //添加过滤器
                .addFilterBefore(jwtAuthenticationTokenFilter, UsernamePasswordAuthenticationFilter.class);
        http    //添加异常处理
                .exceptionHandling()
                .authenticationEntryPoint(authenticationEntryPoint)
                .accessDeniedHandler(accessDeniedHandler);
        http.cors();//允许跨域
    }
```

+++

这里三更给的前端项目运行不起来~~~

后面看看后端结束

+++

### 其他权限校验方法

hasAuthority 常用  

hasAnyAuthority    hasRole   hasAnyRole

hasAnyAuthority方法可以传入多个权限,只有用户有其中一个权限即可访问对应资源

```java
@RequestMapping("/hello")
//    @PreAuthorize("hasAnyAuthority('test', 'admin', 'test1', 'system:dept:list')")//写死test
//    @PreAuthorize("hasAuthority('system:dept:list')")
    @PreAuthorize("hasRole('system:dept:list')")//注意默认进行拼接ROLE_前缀, ROLE_system:dept:list , 对权限关键字有要求
    //hasAnyRole同理
    
    public String hello() {
        return "hello";
    }
```

### 自定义校验方法

SGExpressionRoot.java

```java
@Component("ex")
public class SGExpressionRoot {

    public boolean hasAuthority(String authority){
        //获取当前用户的权限
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        LoginUser loginUser = (LoginUser) authentication.getPrincipal();
        List<String> permissions = loginUser.getPermissions();
        //判断用户权限集合中是否存在authority
        return permissions.contains(authority);
    }
}
```

helloController中使用spel表达式

```java
@RequestMapping("/hello")
@PreAuthorize("@ex.hasAuthority('system:dept:list')") //使用spel表达式自定义校验
    public String hello() {
        return "hello";
    }
```

### 基于配置类校验

SecurityConfig.java

```java
@Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeRequests()
                .antMatchers("/user/login").anonymous()
                .antMatchers("/hello").hasAuthority("system:dept:list")//在这里配置权限
                .anyRequest().authenticated();
        
        http    //添加过滤器
                .addFilterBefore(jwtAuthenticationTokenFilter, UsernamePasswordAuthenticationFilter.class);
        http    //添加异常处理
                .exceptionHandling()
                .authenticationEntryPoint(authenticationEntryPoint)
                .accessDeniedHandler(accessDeniedHandler);
        http.cors();//允许跨域
    }
```

### CSRF

前后端跨站请求伪造

security后端生成一个csrf_token,前端发起请求时需要携带这个csrf_token,后端有过滤器进行校验,如果没有携带或伪造的不允许访问

这个防止cookie攻击

如果前后端分离项目自带token或者不怕跨站攻击,则可以关闭csrf

### 登入成功|失败处理器

AuthenticationSuccessHanlder 进行成功后的处理

这个配置前提是使用登录表单 formLogin

```java
@Component
public class SGFailureHandler implements AuthenticationFailureHandler {
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        System.out.println("认证失败了");
    }
}
```



```java
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private AuthenticationSuccessHandler successHandler;

    @Autowired
    private AuthenticationFailureHandler failureHandler;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.formLogin()
//                配置认证成功处理器
                .successHandler(successHandler)
//                配置认证失败处理器
                .failureHandler(failureHandler);

        http.authorizeRequests().anyRequest().authenticated();
    }
}

```

### 登出成功处理器

```java
@Component
public class SGLogoutSuccessHandler implements LogoutSuccessHandler {
    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        System.out.println("注销成功");
    }
}

```

```java
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private AuthenticationSuccessHandler successHandler;

    @Autowired
    private AuthenticationFailureHandler failureHandler;

    @Autowired
    private LogoutSuccessHandler logoutSuccessHandler;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.formLogin()
//                配置认证成功处理器
                .successHandler(successHandler)
//                配置认证失败处理器
                .failureHandler(failureHandler);

        http.logout()
                //配置注销成功处理器
                .logoutSuccessHandler(logoutSuccessHandler);

        http.authorizeRequests().anyRequest().authenticated();
    }
}
```



































