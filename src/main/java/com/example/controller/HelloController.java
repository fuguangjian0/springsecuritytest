package com.example.controller;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {



    @RequestMapping("/hello")
//    @PreAuthorize("hasAuthority('test')")//写死test
    @PreAuthorize("hasAuthority('system:dept:list')")
    public String hello() {
        return "hello";
    }


}
