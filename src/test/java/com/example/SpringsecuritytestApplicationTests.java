package com.example;

import com.example.entity.User;
import com.example.mapper.MenuMapper;
import com.example.mapper.UserMapper;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import javax.annotation.Resource;
import java.util.List;

@SpringBootTest
class SpringsecuritytestApplicationTests {
    @Resource
    UserMapper mapper;

    //验证数据库
    @Test
    void contextLoads() {
        User user = mapper.selectById(1);
        System.out.println(user);
    }

    @Resource
    private MenuMapper menuMapper;

    @Test
    public void testSelectPermsByUserId() {
        List<String> list = menuMapper.selectPermsByUserId(2L);
        System.out.println(list);
    }

    //加密
    @Test
    void encode() {
        System.out.println(new BCryptPasswordEncoder().encode("1234"));
    }

}
