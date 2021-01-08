package com.supportpotal.supportpotal.listener;

import com.supportpotal.supportpotal.domain.User;
import com.supportpotal.supportpotal.domain.UserPrincipal;
import com.supportpotal.supportpotal.service.LoginAttemptService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class AuthenticationSuccessListener {
    private final LoginAttemptService loginAttemptService;

    @EventListener
    public void onAuthenticationSuccess(AuthenticationSuccessEvent event) {
        Object principal = event.getAuthentication().getPrincipal(); //event값은 service에 loadUserByUsername의 리턴값이다.
        if(principal instanceof UserPrincipal) {
            UserPrincipal user = (UserPrincipal)event.getAuthentication().getPrincipal();
            loginAttemptService.evictUserFromLoginAttemptCache(user.getUsername());
        }
    }
}
