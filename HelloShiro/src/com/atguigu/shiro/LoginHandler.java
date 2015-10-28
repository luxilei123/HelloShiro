package com.atguigu.shiro;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.LockedAccountException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;


@Controller
public class LoginHandler {
	
	@RequestMapping("/shiro-login")
	public String login(@RequestParam(value="username",required=false)String username,
						@RequestParam(value="password",required=false)String password){
		
        Subject currentUser = SecurityUtils.getSubject();

        if (!currentUser.isAuthenticated()) {
            UsernamePasswordToken token = new UsernamePasswordToken(username, password);
            token.setRememberMe(true);
            try {
            	// 调用 Subject#login() 方法会导致 AuthenticatingRealm#doGetAuthenticationInfo 方法被调用
                currentUser.login(token);
            } 
            catch (AuthenticationException ae) {
            	System.out.println("--------》"+ae.getMessage());
            }
        }
		return "list";
	}
}
