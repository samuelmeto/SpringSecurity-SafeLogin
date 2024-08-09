package com.springsecurity.jwt.service;

import com.springsecurity.jwt.dto.RegistrationDto;
import com.springsecurity.jwt.model.AppUser;
import com.springsecurity.jwt.model.AppUserRole;
import com.springsecurity.jwt.repository.AppUserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AppUserService implements UserDetailsService{

    private final AppUserRepository appUserRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public AppUserService(AppUserRepository appUserRepository, BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.appUserRepository = appUserRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return appUserRepository.findAppUserByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }

    public String signUp(RegistrationDto registrationDto) {
        boolean isTaken = appUserRepository.findAppUserByUsername(registrationDto.username()).isPresent();
        if (isTaken) {
            return "Username is already taken";
        }

        AppUser appUser = new AppUser(registrationDto.username(), registrationDto.password(), true, AppUserRole.USER);
        appUser.setPassword(bCryptPasswordEncoder.encode(registrationDto.password()));
        appUserRepository.save(appUser);

        return "Registered successfully";
    }
}