package com.example.jwt.auth;

import com.example.jwt.repository.UserRepository;
import com.example.jwt.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

// http://loaclhost:8080/login

@Service
@RequiredArgsConstructor
public class PrincipalDetailService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println("PrincipalDetailService의 loadUserBysername()");
        User user = userRepository.findByUsername(username);
        return new PrincipalDetails(user);
    }
}
