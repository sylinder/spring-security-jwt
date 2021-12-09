package com.caps.springsecurityjwt.controller;

import com.caps.springsecurityjwt.common.CommonResult;
import com.caps.springsecurityjwt.domain.dto.LoginForm;
import com.caps.springsecurityjwt.domain.dto.RegisterForm;
import com.caps.springsecurityjwt.domain.dto.TokenInfo;
import com.caps.springsecurityjwt.domain.dto.UserDTO;
import com.caps.springsecurityjwt.service.UserService;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/users")
public class UserController {

    private UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping
    public CommonResult<List<UserDTO>> findAllUsers() {
        return userService.findAllUsers();
    }

    @PostMapping("/register")
    public CommonResult<String> register(@RequestBody RegisterForm registerForm) {
        return userService.register(registerForm);
    }

    @PostMapping("/login")
    public CommonResult<TokenInfo> login(@RequestBody LoginForm loginForm) {
        return userService.login(loginForm);
    }
}
