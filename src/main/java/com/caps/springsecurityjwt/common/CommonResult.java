package com.caps.springsecurityjwt.common;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class CommonResult<T> {

    private Boolean success;

    private Integer code;

    private String message;

    private T data;

    public static <T> CommonResult<T> success(T data) {
        return new CommonResult<>(true, 200, null, data);
    }

    public static <T> CommonResult<T> fail(String message) {
        return new CommonResult<>(false, 400, message, null);
    }

    public static <T> CommonResult<T> fail(Integer code, String message) {
        return new CommonResult<>(false, code, message, null);
    }
}
