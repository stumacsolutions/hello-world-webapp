package com.example;

import lombok.Builder;
import lombok.Getter;
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.boot.autoconfigure.security.oauth2.resource.AuthoritiesExtractor;
import org.springframework.boot.autoconfigure.security.oauth2.resource.PrincipalExtractor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

import static org.springframework.security.core.authority.AuthorityUtils.commaSeparatedStringToAuthorityList;

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

    @Configuration
    @Profile("github")
    static class GitHibSecurityConfig {

        @Bean
        AuthoritiesExtractor githubAuthoritiesExtractor() {
            return map -> {
                String username = (String) map.get("login");
                return "stumacsolutions".equals(username) ?
                    commaSeparatedStringToAuthorityList("ROLE_USER,ROLE_ADMIN") :
                    commaSeparatedStringToAuthorityList("ROLE_USER");
            };
        }

        @Bean
        PrincipalExtractor githubPrincipalExtractor() {
            return map -> User.builder()
                .avatarUrl((String) map.get("avatar_url"))
                .name((String) map.get("name"))
                .username((String) map.get("login"))
                .build();
        }
    }

    @Configuration
    @Profile("google")
    static class GoogleHibSecurityConfig {

        @Bean
        AuthoritiesExtractor googleAuthoritiesExtractor() {
            return map -> {
                String username = (String) map.get("email");
                return "stumacsolutions@gmail.com".equals(username) ?
                    commaSeparatedStringToAuthorityList("ROLE_USER,ROLE_ADMIN") :
                    commaSeparatedStringToAuthorityList("ROLE_USER");
            };
        }

        @Bean
        PrincipalExtractor googlePrincipalExtractor() {
            return map -> User.builder()
                .avatarUrl((String) map.get("picture"))
                .name((String) map.get("given_name"))
                .username((String) map.get("email"))
                .build();
        }
    }

    @Getter
    @Builder
    private static class User {
        private String avatarUrl;
        private String name;
        private String username;
    }
}
