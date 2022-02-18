package com.github.demo.configuration;

import org.apache.shiro.authc.Authenticator;
import org.apache.shiro.authc.pam.FirstSuccessfulStrategy;
import org.apache.shiro.authc.pam.ModularRealmAuthenticator;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.mgt.SessionStorageEvaluator;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.spring.web.config.DefaultShiroFilterChainDefinition;
import org.apache.shiro.spring.web.config.ShiroFilterChainDefinition;
import org.apache.shiro.web.mgt.DefaultWebSessionStorageEvaluator;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.github.demo.filter.AnyRolesAuthorizationFilter;
import com.github.demo.filter.JwtAuthFilter;
import com.github.demo.service.UserService;

import javax.servlet.DispatcherType;
import javax.servlet.Filter;

import java.util.Arrays;
import java.util.Map;

/**
 * 校验流程
 * 我们使用Shiro主要做3件事情，1）用户登录时做用户名密码校验；2）用户登录后收到请求时做JWT Token的校验；3）用户权限的校验
 * shiro配置类
 */
@Configuration
public class ShiroConfig {
    /**
     * @Description 注册shiro filter
     * @Param : [securityManager, userService]
     * @Author : liupeng
     * @Date : 2022/2/16 14:28
     */
    @Bean
    public FilterRegistrationBean<Filter> filterRegistrationBean(SecurityManager securityManager,UserService userService) throws Exception{
        FilterRegistrationBean<Filter> filterRegistration = new FilterRegistrationBean<Filter>();
        filterRegistration.setFilter((Filter)shiroFilter(securityManager, userService).getObject());
        filterRegistration.addInitParameter("targetFilterLifecycle", "true");
        filterRegistration.setAsyncSupported(true);
        filterRegistration.setEnabled(true);
        filterRegistration.setDispatcherTypes(DispatcherType.REQUEST,DispatcherType.ASYNC);

        return filterRegistration;
    }
    /**
     * @Description 初始化 Authenticator
     * @Param : [userService]
     * @Author : liupeng
     * @Date : 2022/2/16 14:29
     */
    @Bean
    public Authenticator authenticator(UserService userService) {
        ModularRealmAuthenticator authenticator = new ModularRealmAuthenticator();
        authenticator.setRealms(Arrays.asList(jwtShiroRealm(userService), dbShiroRealm(userService)));
        authenticator.setAuthenticationStrategy(new FirstSuccessfulStrategy());
        return authenticator;
    }
    /**
     * @Description
     *      禁用session, 不保存用户登录状态。保证每次请求都重新认证。
     *     需要注意的是，如果用户代码里调用Subject.getSession()还是可以用session，
     *     如果要完全禁用，要配合下面的noSessionCreation的Filter来实现
     *     因为用了jwt的访问认证，所以要把默认session支持关掉。
     *     这里要做两件事情，一个是ShiroConfig里面的配置.一个在shiroFilterChainDefinition
     *      chainDefinition.addPathDefinition("/**", "noSessionCreation,authcToken");
     * @Param : []
     * @Author : liupeng
     * @Date : 2022/2/16 14:30
     */
    @Bean
    protected SessionStorageEvaluator sessionStorageEvaluator(){
        DefaultWebSessionStorageEvaluator sessionStorageEvaluator = new DefaultWebSessionStorageEvaluator();
        sessionStorageEvaluator.setSessionStorageEnabled(false);
        return sessionStorageEvaluator;
    }
    /**
     * 用于用户名密码登录时认证的realm
     */
    @Bean("dbRealm")
    public Realm dbShiroRealm(UserService userService) {
        DbShiroRealm myShiroRealm = new DbShiroRealm(userService);
        return myShiroRealm;
    }
    /**
     * 用于JWT token认证的realm
     */
    @Bean("jwtRealm")
    public Realm jwtShiroRealm(UserService userService) {
        JWTShiroRealm myShiroRealm = new JWTShiroRealm(userService);
        return myShiroRealm;
    }

    /**
     * 设置过滤器，将自定义的Filter加入
     */
    @Bean("shiroFilter")
    public ShiroFilterFactoryBean shiroFilter(SecurityManager securityManager, UserService userService) {
    	ShiroFilterFactoryBean factoryBean = new ShiroFilterFactoryBean();
        factoryBean.setSecurityManager(securityManager);
        Map<String, Filter> filterMap = factoryBean.getFilters();
        filterMap.put("authcToken", createAuthFilter(userService));
        filterMap.put("anyRole", createRolesFilter());
        factoryBean.setFilters(filterMap);
        //过滤路径
        factoryBean.setFilterChainDefinitionMap(shiroFilterChainDefinition().getFilterChainMap());
        return factoryBean;
    }

    @Bean
    protected ShiroFilterChainDefinition shiroFilterChainDefinition() {
        DefaultShiroFilterChainDefinition chainDefinition = new DefaultShiroFilterChainDefinition();
        //对于登录请求，Filter直接放过，进到LoginController里面。LoginController会调用shiro做用户名和密码的校验，成功后返回token。
        chainDefinition.addPathDefinition("/login", "noSessionCreation,anon");
        chainDefinition.addPathDefinition("/logout", "noSessionCreation,authcToken[permissive]");
        chainDefinition.addPathDefinition("/image/**", "anon");
        chainDefinition.addPathDefinition("/admin/**", "noSessionCreation,authcToken,anyRole[admin,manager]"); //只允许admin或manager角色的用户访问
        chainDefinition.addPathDefinition("/article/list", "noSessionCreation,authcToken");
        chainDefinition.addPathDefinition("/article/*", "noSessionCreation,authcToken[permissive]");
        chainDefinition.addPathDefinition("/**", "noSessionCreation,authcToken");
        return chainDefinition;
    }

    protected JwtAuthFilter createAuthFilter(UserService userService){
        return new JwtAuthFilter(userService);
    }

    protected AnyRolesAuthorizationFilter createRolesFilter(){
        return new AnyRolesAuthorizationFilter();
    }

}
