package me.nn.securityexam.token;


import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.NoSuchElementException;

@Service
public class UserDetailServiceImpl implements UserDetailsService {


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        try {
                org.springframework.security.core.userdetails.User.UserBuilder builder = null;
                builder = org.springframework.security.core.userdetails.User.withUsername(username);
                builder.password("123");
                builder.roles(String.valueOf(12));
                return builder.build();
//            return userRepository.findById(username).map(user -> {
//                org.springframework.security.core.userdetails.User.UserBuilder builder = null;
//                builder = org.springframework.security.core.userdetails.User.withUsername(username);
//                builder.password(user.getPassword());
//                builder.roles(String.valueOf(user.getAuthorityId()));
//                return builder.build();
//            }).get();
        } catch (NoSuchElementException e) {
            throw new UsernameNotFoundException("User not found.");
        }
    }
}
