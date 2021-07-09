package com.hyperedu.service;

import com.hyperedu.model.User;
import com.hyperedu.model.dto.UserSignUpDTO;

import java.util.List;

/**
 * Created by fan.jin on 2016-10-15.
 */

public interface UserService {
    User findById(Long id);
    User findByUsername(String username);
    List<User> findAll ();
    void signUp(UserSignUpDTO userSignUpDTO) throws Exception;
}
