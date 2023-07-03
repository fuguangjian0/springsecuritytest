package com.example.service.impl;

import com.example.entity.LoginUser;
import com.example.entity.ResponseResult;
import com.example.entity.User;
import com.example.service.LoginService;
import com.example.utils.JwtUtil;
import com.example.utils.RedisCache;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.HashMap;
import java.util.Objects;

@Service
public class LoginServiceImpl implements LoginService {

    @Resource
    private AuthenticationManager authenticationManager;

    @Resource
    private RedisCache redisCache;

    @Override
    public ResponseResult login(User user) {
        // 把用户名&密码封装到 Authentication 对象
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(user.getUserName(), user.getPassword());
        Authentication authenticate = authenticationManager.authenticate(authenticationToken);
        if (Objects.isNull(authenticate)) throw new RuntimeException("登录失败");

        // 生成jwt
        LoginUser loginUser = (LoginUser) authenticate.getPrincipal();
        //获取数据库id
        Long id = loginUser.getUser().getId();
        //id转成字符串方便使用
        String userId = id.toString();


        //把loginUser对象存入redis中, 对应的userId作为key, key:value ['login:125xx' : loginUser对象]
        redisCache.setCacheObject("login:"+userId, loginUser);

        //id进行加密
        String jwt = JwtUtil.createJWT(userId);
        HashMap<String, String> map = new HashMap<>();
        map.put("token", jwt);
        //把map返回给前端 { 'token': jwt }
        return new ResponseResult(200, "登录成功", map);
    }




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


}
