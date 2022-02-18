package com.github.demo.configuration;

import java.util.List;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.crypto.hash.Sha256Hash;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.github.demo.dto.UserDto;
import com.github.demo.service.UserService;

public class DbShiroRealm extends AuthorizingRealm {
	private final Logger log = LoggerFactory.getLogger(DbShiroRealm.class);

	//数据库存储的用户密码的加密salt，正式环境不能放在源代码里
	private static final String encryptSalt = "F12839WhsnnEV$#23b";
	private UserService userService;
	
	public DbShiroRealm(UserService userService) {
		this.userService = userService;
		//因为数据库中的密码做了散列，所以使用shiro的散列Matcher
		this.setCredentialsMatcher(new HashedCredentialsMatcher(Sha256Hash.ALGORITHM_NAME));
	}
	
	@Override
    public boolean supports(AuthenticationToken token) {
        return token instanceof UsernamePasswordToken;
    }
	/**
	 *  这一步我们根据token给的用户名，去数据库查出加密过用户密码，
	 *  然后把加密后的密码和盐值一起发给shiro，让它做比对
	 */
	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
		UsernamePasswordToken userpasswordToken = (UsernamePasswordToken)token;
		String username = userpasswordToken.getUsername();
		UserDto user = userService.getUserInfo(username);
		if(user == null)
			throw new AuthenticationException("用户名或者密码错误");
		
		return new SimpleAuthenticationInfo(user, user.getEncryptPwd(), ByteSource.Util.bytes(encryptSalt), "dbRealm");
	}

	/**
	 *  角色权限
	 *  这里需要注意一下的就是Shiro默认不会缓存角色信息，所以这里调用service的方法获取角色强烈建议从缓存中获取。
	 */
	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {      
        SimpleAuthorizationInfo simpleAuthorizationInfo = new SimpleAuthorizationInfo();
        UserDto user = (UserDto) principals.getPrimaryPrincipal();
        List<String> roles = user.getRoles();
        if(roles == null) {
            roles = userService.getUserRoles(user.getUserId());
            user.setRoles(roles);
        }
        if (roles != null)
            simpleAuthorizationInfo.addRoles(roles);

        return simpleAuthorizationInfo;
	}

	
}
