package com.example;

import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableOAuth2Sso
class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
            .antMatchers("/admin/**").hasRole("ADMIN")
            .antMatchers("/", "/login**", "/css/**", "/img/**", "/webjars/**").permitAll()
            .anyRequest().authenticated()
            .and()
            .csrf().ignoringAntMatchers("/admin/h2-console/*")
            .and()
            .logout().logoutSuccessUrl("/").permitAll()
            .and()
            .headers().frameOptions().sameOrigin();
    }
}
