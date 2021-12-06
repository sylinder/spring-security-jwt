package com.caps.springsecurityjwt.controller;

import com.caps.springsecurityjwt.common.CommonResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {

    @GetMapping("/hello")
    public CommonResult<String> hello() {
        return CommonResult.success("Hello Caps");
    }

    @GetMapping("/test")
    public CommonResult<String> test() {
        return CommonResult.fail("test");
    }
}
