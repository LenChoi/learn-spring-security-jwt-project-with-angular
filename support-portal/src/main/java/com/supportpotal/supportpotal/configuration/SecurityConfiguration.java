package com.supportpotal.supportpotal.configuration;

import com.supportpotal.supportpotal.constant.SecurityConstant;
import com.supportpotal.supportpotal.filter.JwtAccessDeniedHandler;
import com.supportpotal.supportpotal.filter.JwtAuthenticationEntryPoint;
import com.supportpotal.supportpotal.filter.JwtAuthorizationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true) //메소드 시큐리티 권한주는 어노테이션
@RequiredArgsConstructor
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    private final JwtAuthorizationFilter jwtAuthorizationFilter;
    private final JwtAccessDeniedHandler jwtAccessDeniedHandler;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final @Qualifier("userDetailsService") UserDetailsService userDetailsService; //이거 아닐수도 @Qualifier
    private final BCryptPasswordEncoder bCryptPasswordEncoder;


    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(bCryptPasswordEncoder);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable().cors().and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)//jwt에서는 세션 추적이 필요없기 떄문에
                .and().authorizeRequests().antMatchers(SecurityConstant.PUBLIC_URLS).permitAll() //공개 주소만 허용
                .anyRequest().authenticated() //나머지는 인증
                .and()
                .exceptionHandling().accessDeniedHandler(jwtAccessDeniedHandler)
                .authenticationEntryPoint(jwtAuthenticationEntryPoint)
                .and()
                .addFilterBefore(jwtAuthorizationFilter, UsernamePasswordAuthenticationFilter.class);
                //username필터 전에 우리가 만든 필터가 동작한다
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    /**
     *     AuthenticationManager 를 사용하여, 원하는 시점에 로그인을 해보자.
     *     지금은 항상 어떤 로그인이든지, POST /login 경로에서만 로그인이 되었었다.
     *     AuthenticationManager 를 이용하여, 원하는 시점에 로그인이 될 수 있도록 바꿔보자.
     *     먼저, AuthenticationManager 를 외부에서 사용 하기 위해, AuthenticationManagerBean 을 이용하여
     *     Sprint Securtiy 밖으로 AuthenticationManager 빼 내야 한다.
     *     이렇게 하지 않으면 AuthenticationManager 를 injection 할 수 없다.
     *     위 메서드를 주석 처리하고, 컨트롤러에서 AutehtnciationManager 를 @Autowired 하면 컴파일 에러가 난다.
     */

}
