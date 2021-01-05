package com.supportpotal.supportpotal.utility;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.supportpotal.supportpotal.constant.SecurityConstant;

import static com.auth0.jwt.algorithms.Algorithm.HMAC512;
import static  com.supportpotal.supportpotal.constant.SecurityConstant.*;
import static java.util.Arrays.stream;

import com.supportpotal.supportpotal.domain.UserPrincipal;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

@Component
public class JWTTokenProvider {

    @Value("${jwt.secret}")
    private String secret;

    public String generateJwtToken(UserPrincipal userPrincipal) { //토큰 생성
        String[] claims = getClaimsFromUser(userPrincipal);
        return JWT.create().withIssuer(GET_ARRAYS_LLC).withAudience(GET_ARRAYS_ADMINISTRATION)
                .withIssuedAt(new Date()).withSubject(userPrincipal.getUsername())
                .withArrayClaim(AUTHORITIES, claims).withExpiresAt(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .sign(HMAC512(secret.getBytes()));
    }
    
    public List<GrantedAuthority> getAuthorities(String token) { //토큰에서 모든 인가를 가져온다 2.1
        String[] claims = getClaimsFromToken(token);
        return stream(claims).map(SimpleGrantedAuthority::new).collect(Collectors.toList());
    }

    //인증을 가져오는 것/ UsernamePasswordAuthenticationToken은 authentication의 구현체인데 구현체 만이
    // authentication Manager에서 인증이 가능하다
    public Authentication getAuthentication(String username, List<GrantedAuthority> authorities, HttpServletRequest request) {
        UsernamePasswordAuthenticationToken userPasswordAuthToken = new
                UsernamePasswordAuthenticationToken(username, null, authorities); //인증된 토큰이라서 credential이 필요 없다
        userPasswordAuthToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        //request로 부터 user에 관한 정보를 넣는다는것 같음 잘모르겠음
        return userPasswordAuthToken; //인증을 가져오고나서 시큐리티 컨텍스트에 넣는다.
    }

    public boolean isTokenValid(String username, String token) { //토큰이 검증된 것인지 확인
        JWTVerifier verifier = getJWTVerifier();
        return StringUtils.isNotEmpty(username) && !isTokenExpired(verifier, token);
    }

    public String getSubject(String token) {
        JWTVerifier verifier = getJWTVerifier();
        return verifier.verify(token).getSubject();
    }

    private boolean isTokenExpired(JWTVerifier verifier, String token) {
        Date expiration = verifier.verify(token).getExpiresAt();
        return expiration.before(new Date());
    }

    private String[] getClaimsFromToken(String token) {//2.2
        JWTVerifier verifier = getJWTVerifier();
        return verifier.verify(token).getClaim(AUTHORITIES).asArray(String.class); //토큰에서 인가를 가져와 리스트를 배열로 반환
    }

    private JWTVerifier getJWTVerifier() {
        JWTVerifier verifier;
        try {
            Algorithm algorithm = HMAC512(secret);
            verifier = JWT.require(algorithm).withIssuer(GET_ARRAYS_LLC).build(); //알고리즘과 토큰 발행자를 넣어서 검사
        } catch (JWTVerificationException exception) { //만약 검증되지 않으면 에러 출력
            throw new JWTVerificationException(TOKEN_CANNOT_BE_VERIFIED);
        }
        return verifier;
    }

    public String[] getClaimsFromUser(UserPrincipal user) { //유저의 Claim 배열을 리턴 1.1
        List<String> authorities = new ArrayList<>();
        for (GrantedAuthority grantedAuthority : user.getAuthorities()) {
            authorities.add(grantedAuthority.getAuthority());
        }
        return authorities.toArray(new String[0]);
    }
}
