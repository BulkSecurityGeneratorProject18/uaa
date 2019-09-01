package com.hodgepodge.security.service.api;

import com.hodgepodge.security.model.User;

public interface UserService {

    User registerUser(final User user);

    User updateUser(final User user);
}
