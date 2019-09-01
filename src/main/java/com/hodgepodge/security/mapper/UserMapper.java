package com.hodgepodge.security.mapper;

import com.hodgepodge.security.model.User;
import com.hodgepodge.security.payload.user.RegistrationUser;
import com.hodgepodge.security.payload.user.SaveUser;
import com.hodgepodge.security.payload.user.UserResponse;
import org.mapstruct.Mapper;

@Mapper(componentModel = "spring")
public interface UserMapper {

    User registrationUserToUser(final RegistrationUser regUser);

    User saveUserToUser(final SaveUser saveUser);

    UserResponse userToUserResponse(final User user);
}
