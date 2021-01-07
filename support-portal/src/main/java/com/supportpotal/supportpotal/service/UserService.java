package com.supportpotal.supportpotal.service;

import com.supportpotal.supportpotal.domain.User;
import com.supportpotal.supportpotal.exception.domain.EmailExistException;
import com.supportpotal.supportpotal.exception.domain.UserNotFoundException;
import com.supportpotal.supportpotal.exception.domain.UsernameExistException;

import java.util.List;

public interface UserService {
    User register(String firstName, String lastName, String username, String email) throws UserNotFoundException, UsernameExistException, EmailExistException;

    List<User> getUsers();

    User findUserByUsername(String username);

    User findUserByEmail(String email);


}
