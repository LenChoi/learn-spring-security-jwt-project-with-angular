package com.supportpotal.supportpotal.resource;

import com.supportpotal.supportpotal.constant.SecurityConstant;
import com.supportpotal.supportpotal.domain.User;
import com.supportpotal.supportpotal.domain.UserPrincipal;
import com.supportpotal.supportpotal.exception.domain.EmailExistException;
import com.supportpotal.supportpotal.exception.domain.ExceptionHandling;
import com.supportpotal.supportpotal.exception.domain.UserNotFoundException;
import com.supportpotal.supportpotal.exception.domain.UsernameExistException;
import com.supportpotal.supportpotal.service.UserService;
import com.supportpotal.supportpotal.utility.JWTTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(path = {"/","/user"})
@RequiredArgsConstructor
public class UserResource extends ExceptionHandling {
    private final UserService userService;
    private final AuthenticationManager authenticationManager;
    private final JWTTokenProvider jwtTokenProvider;

    @PostMapping("/login")
    public ResponseEntity<User> login(@RequestBody User user){
        authenticate(user.getUsername(), user.getPassword());
        User loginUser = userService.findUserByUsername(user.getUsername());
        UserPrincipal userPrincipal = new UserPrincipal(loginUser);
        HttpHeaders jwtHeader = getJwtHeader(userPrincipal);
        return new ResponseEntity<>(loginUser, jwtHeader, HttpStatus.OK);
    }

    @PostMapping("/register")
    public ResponseEntity<User> register(@RequestBody User user) throws UserNotFoundException , UsernameExistException, EmailExistException {
        User newUser = userService.register(user.getFirstName(), user.getLastName(), user.getUsername(), user.getEmail());
        return new ResponseEntity<>(newUser, HttpStatus.OK);
    }

    private HttpHeaders getJwtHeader(UserPrincipal user) {
        HttpHeaders headers = new HttpHeaders();
        jwtTokenProvider.generateJwtToken(user);
        headers.add(SecurityConstant.JWT_TOKEN_HEADER, jwtTokenProvider.generateJwtToken(user));
        return headers;
    }

    private void authenticate(String username, String password) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
    }
}
