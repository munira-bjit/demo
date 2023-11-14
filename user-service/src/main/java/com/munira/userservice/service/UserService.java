package com.munira.userservice.service;

import com.munira.userservice.dto.UserDto;
import com.munira.userservice.entity.UserEntity;
import org.springframework.security.core.userdetails.UserDetails;

public interface UserService {
    UserDto createUser(UserDto userDto) throws Exception;
    UserDto getUserByUserId(Long id) throws Exception;
    UserDto getUser(String email) throws Exception;
    UserDetails loadUserByUsername(String email) throws Exception;
    UserDto getUserProfile() throws Exception;

    void editUserProfile(UserDto userDto) throws Exception;

}
