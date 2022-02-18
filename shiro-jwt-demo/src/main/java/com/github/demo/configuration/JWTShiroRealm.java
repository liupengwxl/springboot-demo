package com.github.demo.configuration;

import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.tomcat.util.net.openssl.ciphers.Authentication;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.github.demo.dto.UserDto;
import com.github.demo.service.UserService;


/**
 * 自定义身份认证
 * 基于HMAC（ 散列消息认证码）的控制域
 */

public class JWTShiroRealm extends AuthorizingRealm {
	private final Logger log = LoggerFactory.getLogger(JWTShiroRealm.class);

    protected UserService userService;

    public JWTShiroRealm(UserService userService){
        this.userService = userService;
        //这里使用我们自定义的Matcher
        this.setCredentialsMatcher(new JWTCredentialsMatcher());
    }

    /**
     * 限定这个Realm只支持我们自定义的JWT Token
     */
    @Override
    public boolean supports(AuthenticationToken token) {
        return token instanceof JWTToken;
    }

    /**
     * 和logincontroller登录一样，也是获取用户的salt值，给到shiro，由shiro来调用matcher来做认证
     * 认证信息.(身份验证) : Authentication 是用来验证用户身份
     * 默认使用此方法进行用户名正确与否验证，错误抛出异常即可。
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authcToken) throws AuthenticationException {    
        JWTToken jwtToken = (JWTToken) authcToken;
        String token = jwtToken.getToken();
        
        UserDto user = userService.getJwtTokenInfo(JwtUtils.getUsername(token));
        if(user == null)
            throw new AuthenticationException("token过期，请重新登录");

        SimpleAuthenticationInfo authenticationInfo = new SimpleAuthenticationInfo(user, user.getSalt(), "jwtRealm");

        return authenticationInfo;
    }
    /**
     * @Description 在JWT Realm里面，因为没有存储角色信息，所以直接返回空就可以了
     * @Param : [principals]
     * @Author : liupeng
     * @Date : 2022/2/18 16:36
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        return new SimpleAuthorizationInfo();
    }
}
