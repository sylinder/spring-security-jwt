package com.caps.springsecurityjwt.domain.dto;

import lombok.Data;

import javax.validation.constraints.NotBlank;

@Data
public class RegisterForm {

    @NotBlank(message = "username can not be null.")
    private String username;

    @NotBlank(message = "password can not be null.")
    private String password;
}
