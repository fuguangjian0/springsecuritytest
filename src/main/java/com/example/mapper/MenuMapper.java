package com.example.mapper;


import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.example.entity.Menu;

import java.util.List;

public interface MenuMapper extends BaseMapper<Menu> {

    // 多表联查,mp无能为力
    List<String> selectPermsByUserId(Long userId);


}
