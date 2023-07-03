package com.example.controller;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {



    @RequestMapping("/hello")
//    @PreAuthorize("hasAnyAuthority('test', 'admin', 'test1', 'system:dept:list')")//写死test
//    @PreAuthorize("hasAuthority('system:dept:list')")
    @PreAuthorize("@ex.hasAuthority('system:dept:list')")//注意默认进行拼接ROLE_前缀, ROLE_system:dept:list , 对权限关键字有要求
    //hasAnyRole同理
    public String hello() {
        return "hello";
    }


}
