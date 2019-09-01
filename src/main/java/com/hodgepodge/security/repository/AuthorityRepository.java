package com.hodgepodge.security.repository;

import com.hodgepodge.security.model.Authority;
import com.hodgepodge.security.model.AuthorityName;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface AuthorityRepository extends JpaRepository<Authority, String> {

    Optional<Authority> findByRole(AuthorityName authorityName);
}
