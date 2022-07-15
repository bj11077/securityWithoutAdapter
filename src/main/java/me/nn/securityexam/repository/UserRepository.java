package me.nn.securityexam.repository;

import me.nn.securityexam.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User,Long> {
}
