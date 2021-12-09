package com.caps.springsecurityjwt.repository;

import com.caps.springsecurityjwt.domain.entity.UserPo;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<UserPo, Long> {
    UserPo findByUsername(String username);
}
