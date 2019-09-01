package com.hodgepodge.security.repository;

import com.hodgepodge.security.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, String> {

    Optional<User> findById(final String id);

    Optional<User> findByEmail(final String email);

    Boolean existsByEmail(final String email);
}
