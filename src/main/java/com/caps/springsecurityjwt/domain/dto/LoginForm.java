package com.caps.springsecurityjwt.domain.dto;

import lombok.Data;

import javax.validation.constraints.NotBlank;

@Data
public class LoginForm {

    @NotBlank(message = "username can not be blank.")
    private String username;

    @NotBlank(message = "password can not be blank.")
    private String password;
}
