package com.github.demo.filter;

import com.github.demo.configuration.JWTToken;
import com.github.demo.configuration.JwtUtils;
import com.github.demo.dto.UserDto;
import com.github.demo.service.UserService;

import org.apache.commons.lang3.BooleanUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpStatus;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.authc.AuthenticatingFilter;
import org.apache.shiro.web.util.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.context.request.async.WebAsyncManager;
import org.springframework.web.context.request.async.WebAsyncUtils;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;

public class JwtAuthFilter extends AuthenticatingFilter {
	private final Logger log = LoggerFactory.getLogger(JwtAuthFilter.class);
	
    private static final int tokenRefreshInterval = 300;
    private UserService userService;

    public JwtAuthFilter(UserService userService){
        this.userService = userService;
        this.setLoginUrl("/login");
    }

    @Override
    protected boolean preHandle(ServletRequest request, ServletResponse response) throws Exception {
        HttpServletRequest httpServletRequest = WebUtils.toHttp(request);
        if (httpServletRequest.getMethod().equals(RequestMethod.OPTIONS.name()))
            //对于OPTION请求做拦截，不做token校验
            return false;

        return super.preHandle(request, response);
    }
   /**
    * @Description 跨域支持
    *     对于前后端分离的项目，一般都需要跨域访问，这里需要做两件事，
    *     一个是在JwtFilter的postHandle中在头上加上跨域支持的选项
    *      另一个需要添加一个ResponseBodyAdvice实现类
    * @Param :
    * @Author : liupeng
    * @Date : 2022/2/18 16:46
    */
   @Override
    protected void postHandle(ServletRequest request, ServletResponse response){
        this.fillCorsHeader(WebUtils.toHttp(request), WebUtils.toHttp(response));
        request.setAttribute("jwtShiroFilter.FILTERED", true);
    }

    /**
     * 父类会在请求进入拦截器后调用该方法，返回true则继续，
     * 返回false则会调用onAccessDenied()。
     * 这里在不通过时，还调用了isPermissive()方法,
     * 如果filter的拦截配置那里配置了permissive参数，
     * 即使登录认证没通过，因为isPermissive返回true，还是会让请求继续下去的。shiroConfig里面的配置了
     * "/logout", "noSessionCreation,authcToken[permissive]"就是这么简单直接，字符串匹配
     * 当然这里也可以重写这个方法插入更复杂的逻辑。
     * 这么做的目的是什么呢？因为有时候我们对待请求，并不都是非黑即白，比如登出操作，如果用户带的token是正确的，
     * 我们会将保存的用户信息清除；如果带的token是错的，也没关系，大不了不干啥，没必要返回错误给用户。
     * 还有一个典型的案例，比如我们阅读博客，匿名用户也是可以看的。只是如果是登录用户，我们会显示额外的东西，
     * 比如是不是点过赞等。所以认证这里的逻辑就是token是对的，我会给把人认出来；是错的，我也直接放过，
     * 留给controller来决定怎么区别对待
     */
    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) {
        if(this.isLoginRequest(request, response))
            return true;
        Boolean afterFiltered = (Boolean)(request.getAttribute("jwtShiroFilter.FILTERED"));
        if( BooleanUtils.isTrue(afterFiltered))
        	return true;

        boolean allowed = false;
        try {
            allowed = executeLogin(request, response);
        } catch(IllegalStateException e){ //not found any token
            log.error("Not found any token");
        }catch (Exception e) {
            log.error("Error occurs when login", e);
        }
        return allowed || super.isPermissive(mappedValue);
    }

    /**
     * 这里重写了父类的方法，使用我们自己定义的Token类，提交给shiro。
     * 这个方法返回null的话会直接抛出异常，进入isAccessAllowed（）的异常处理逻辑。
     */
    @Override
    protected AuthenticationToken createToken(ServletRequest servletRequest, ServletResponse servletResponse) {
        String jwtToken = getAuthzHeader(servletRequest);
        if(StringUtils.isNotBlank(jwtToken)&&!JwtUtils.isTokenExpired(jwtToken))
            return new JWTToken(jwtToken);

        return null;
    }

    /**
     * 如果这个Filter在之前isAccessAllowed（）方法中返回false,
     * 则会进入这个方法。我们这里直接返回错误的response
     */
    @Override
    protected boolean onAccessDenied(ServletRequest servletRequest, ServletResponse servletResponse) throws Exception {
        HttpServletResponse httpResponse = WebUtils.toHttp(servletResponse);
        httpResponse.setCharacterEncoding("UTF-8");
        httpResponse.setContentType("application/json;charset=UTF-8");
        httpResponse.setStatus(HttpStatus.SC_NON_AUTHORITATIVE_INFORMATION);
        fillCorsHeader(WebUtils.toHttp(servletRequest), httpResponse);
        return false;
    }

    /**
     *  如果Shiro Login认证成功，会进入该方法，等同于用户名密码登录成功，我们这里还判断了是否要刷新Token
     */
    @Override
    protected boolean onLoginSuccess(AuthenticationToken token, Subject subject, ServletRequest request, ServletResponse response) throws Exception {
        HttpServletResponse httpResponse = WebUtils.toHttp(response);
        String newToken = null;
        if(token instanceof JWTToken){
            JWTToken jwtToken = (JWTToken)token;
            UserDto user = (UserDto) subject.getPrincipal();
            boolean shouldRefresh = shouldTokenRefresh(JwtUtils.getIssuedAt(jwtToken.getToken()));
            if(shouldRefresh) {
                newToken = userService.generateJwtToken(user.getUsername());
            }
        }
        if(StringUtils.isNotBlank(newToken))
            httpResponse.setHeader("x-auth-token", newToken);

        return true;
    }

    /**
     * 如果调用shiro的login认证失败，会回调这个方法，这里我们什么都不做，因为逻辑放到了onAccessDenied（）中。
     */
    @Override
    protected boolean onLoginFailure(AuthenticationToken token, AuthenticationException e, ServletRequest request, ServletResponse response) {
        log.error("Validate token fail, token:{}, error:{}", token.toString(), e.getMessage());
        return false;
    }

    protected String getAuthzHeader(ServletRequest request) {
        HttpServletRequest httpRequest = WebUtils.toHttp(request);
        String header = httpRequest.getHeader("x-auth-token");
        return StringUtils.removeStart(header, "Bearer ");
    }

    /**
     * @Description 就是如果用户这次的token校验通过后，我们还会顺便看看token要不要刷新，
     * 如果需要刷新则将新的token放到header里面。
     * 这样做的目的是防止token丢了之后，别人可以拿着一直用。我们这里是固定时间刷新。
     * 安全性要求更高的系统可能每次请求都要求刷新，或者是每次POST，PUT等修改数据的请求后必须刷新。判断逻辑如下：
     * @Param : [issueAt]
     * @Author : liupeng
     * @Date : 2022/2/18 16:30
     */
    protected boolean shouldTokenRefresh(Date issueAt){
        LocalDateTime issueTime = LocalDateTime.ofInstant(issueAt.toInstant(), ZoneId.systemDefault());
        return LocalDateTime.now().minusSeconds(tokenRefreshInterval).isAfter(issueTime);
    }

    protected void fillCorsHeader(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse){
        httpServletResponse.setHeader("Access-control-Allow-Origin", httpServletRequest.getHeader("Origin"));
        httpServletResponse.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS,HEAD");
        httpServletResponse.setHeader("Access-Control-Allow-Headers", httpServletRequest.getHeader("Access-Control-Request-Headers"));
    }
}
