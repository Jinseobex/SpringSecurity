package com.zerock.j09.user.config;

import com.zerock.j09.user.security.CustomAccessDeniedHandler;
import com.zerock.j09.user.security.CustomHttp403ForbiddenEntryPoint;
import com.zerock.j09.user.security.filter.ApiCheckFilter;
import com.zerock.j09.user.security.filter.ApiLoginFilter;
import com.zerock.j09.user.security.handler.LoginFailHandler;
import lombok.extern.log4j.Log4j2;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@Log4j2
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    {
        log.info("SecurityConfig......................");
        log.info("SecurityConfig......................");
        log.info("SecurityConfig......................");
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AccessDeniedHandler accessDeniedHandler(){
        return new CustomAccessDeniedHandler();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        log.info("configure.......................");

        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
//        http.authorizeRequests()
//                .antMatchers("/sample/all").permitAll()
//                .antMatchers("/sample/login").permitAll()
//                .antMatchers("/sample/member").hasRole("USER");
//
//        http.formLogin();
//        http.exceptionHandling().accessDeniedHandler(accessDeniedHandler());

        http.csrf().disable();
        http.addFilterBefore(apiCheckFilter(), UsernamePasswordAuthenticationFilter.class);
        http.addFilterBefore(apiLoginFilter(), UsernamePasswordAuthenticationFilter.class);
    }

    @Bean
    public ApiCheckFilter apiCheckFilter() {
        return new ApiCheckFilter("/api/board/**/*");
    }

    @Bean
    public ApiLoginFilter apiLoginFilter() throws Exception {

        ApiLoginFilter apiLoginFilter = new ApiLoginFilter("/login", authenticationManager());
        apiLoginFilter.setAuthenticationFailureHandler((new LoginFailHandler()));

        return apiLoginFilter;
    }


}
