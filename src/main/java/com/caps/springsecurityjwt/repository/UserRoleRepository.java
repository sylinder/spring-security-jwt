package com.caps.springsecurityjwt.repository;

import com.caps.springsecurityjwt.domain.entity.UserRolePo;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface UserRoleRepository extends JpaRepository<UserRolePo, Long> {
    List<UserRolePo> findByUsername(String username);
}
