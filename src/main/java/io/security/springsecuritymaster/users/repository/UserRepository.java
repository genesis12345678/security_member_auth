package io.security.springsecuritymaster.users.repository;

import io.security.springsecuritymaster.domain.entity.Account;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<Account, String> {
    Account findByUsername(String username);
}
