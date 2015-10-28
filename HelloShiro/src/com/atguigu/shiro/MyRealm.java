package com.atguigu.shiro;

import java.util.HashSet;
import java.util.Set;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;

public class MyRealm extends AuthorizingRealm {

	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(
			AuthenticationToken token) throws AuthenticationException {
		// 利用 token 传入的信息查询数据库. 得到其对应的记录
		UsernamePasswordToken usernamePasswordToken = (UsernamePasswordToken) token;
		String username = usernamePasswordToken.getUsername();
		System.out.println("利用用户名: " + username + "查询数据库!");

		if (username == null) {
			throw new UnknownAccountException("用户名:" + username + "不存在!");
		}

		// 若查询的有结果, 则返回 AuthenticationInfo 接口的 SimpleAuthenticationInfo 实现类对象
		// 返回的认证信息
		String principal = username;
		// 从数据表中查询得到的密码, 该密码应该是加密之后的.
		Object hashedCredentials = "65d851f5ff31b38d12eb7a00b6e644c5";
		// 当前 Realm 的 name, 通常通过调用 getName() 方法得到
		String realmName = getName();
		// 设置盐值. 盐值也是从数据表中获取的.
		String salt = "wwww.atguigu.com";
		ByteSource credentialsSalt = ByteSource.Util.bytes("wwww.atguigu.com"
				.getBytes());

		SimpleAuthenticationInfo info = new SimpleAuthenticationInfo(principal,
				hashedCredentials, credentialsSalt, realmName);
		return info;
	}

	public static void main(String[] args) {
		// MD5 盐值加密的算法
		String hashAlgorithmName = "MD5";
		String credentials = "123456";
		String saltSource = "wwww.atguigu.com";
		ByteSource salt = ByteSource.Util.bytes("wwww.atguigu.com".getBytes());
		int hashIterations = 1024;

		Object result = new SimpleHash(hashAlgorithmName, credentials, salt,
				hashIterations);
		System.out.println(result);
		// 65d851f5ff31b38d12eb7a00b6e644c5
		System.out.println(result.toString().equals(
				"65d851f5ff31b38d12eb7a00b6e644c5"));
	}

	// 授权的方式. 即若需要访问受保护的资源, 检查用户是否有对应的权限, 则调用该方法.
	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(
			PrincipalCollection principals) {
		// 从 PrincipalCollection 中获取用户的登陆信息
		Object principal = principals.getPrimaryPrincipal();
		// 在根据 principal 从数据库中获取其所对应的权限
		System.out.println("利用 principal: " + principal + "查询对应的权限!");

		Set<String> roles = new HashSet<>();
		roles.add("user");

		if ("admin".equals(principal)) {
			roles.add("admin");
		}

		SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
		info.addRoles(roles);
		return info;
	}

	/**
	 * 初始化
	 */
	@Override
	protected void onInit() {
		super.onInit();
	}
}
