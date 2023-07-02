package com.example.controller;

import com.example.entity.ResponseResult;
import com.example.entity.User;
import com.example.service.LoginService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.Resource;

@RestController
public class LoginController {

    @Resource
    LoginService service;

    @PostMapping("/user/login")
    public ResponseResult login(@RequestBody User user) {
        return service.login(user);
    }

    @RequestMapping("/user/logout")
    public ResponseResult logout() {
        return service.logout();
    }

}
