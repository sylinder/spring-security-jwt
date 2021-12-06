package com.caps.springsecurityjwt.exception;

import com.caps.springsecurityjwt.common.CommonResult;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(CommonException.class)
    public CommonResult<String> handleCommonException(CommonException exception) {
        return CommonResult.fail(exception.getMessage());
    }
}
