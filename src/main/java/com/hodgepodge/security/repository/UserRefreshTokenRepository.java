package com.hodgepodge.security.repository;

import com.hodgepodge.security.model.UserRefreshToken;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRefreshTokenRepository extends CrudRepository<UserRefreshToken, Long> {

    Optional<UserRefreshToken> findByRefreshToken(final String refreshToken);
}