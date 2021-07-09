package com.hyperedu.service.impl;

import java.util.List;

import com.hyperedu.model.dto.UserSignUpDTO;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import com.hyperedu.model.User;
import com.hyperedu.repository.UserRepository;
import com.hyperedu.service.UserService;

/**
 * Created by fan.jin on 2016-10-15.
 */
@RequiredArgsConstructor
@Service
public class UserServiceImpl implements UserService {

  @Autowired
  private UserRepository userRepository;

  @Autowired
  private PasswordEncoder passwordEncoder;

  @Override
  public User findByUsername(String username) throws UsernameNotFoundException {
    User u = userRepository.findByUsername(username);
    return u;
  }

  public User findById(Long id) throws AccessDeniedException {
    User u = userRepository.findById(id).orElse(null);
    return u;
  }

  public List<User> findAll() throws AccessDeniedException {
    List<User> result = userRepository.findAll();
    return result;
  }

  @Override
  public void signUp(final UserSignUpDTO userSignUpDTO) throws Exception {

    System.out.println(userSignUpDTO.getPassword());
    System.out.println(userSignUpDTO.getUsername());

    User user = User.builder()
      .username(userSignUpDTO.getUsername())
      .password(passwordEncoder.encode(userSignUpDTO.getPassword()))
      .enabled(true)
      .build();

    userRepository.save(user);
    //userRepository.saveByQuery(userSignUpDTO.getUsername(),userSignUpDTO.getPassword());
  }
}
