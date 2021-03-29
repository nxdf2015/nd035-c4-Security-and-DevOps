package com.example.demo.model.persistence;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class UserAuth implements UserDetails {
    String username,password;

    UserAuth(User user){
        username = user.getUsername();

    }

    public UserAuth(String username, String password){
        this.username = username;
        this.password = password;
    }

    public UserAuth() {
    }

    public static UserDetails from(User user) {
       return   new UserAuth(user.getUsername(),user.getPassword());
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return new ArrayList<>();
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public String toString() {
        return "UserAuth{" +
                "username='" + username + '\'' +
                ", password='" + password + '\'' +
                '}';
    }
}
