package io.security.springsecuritymaster.security.config;

import io.security.springsecuritymaster.security.dsl.RestApiDsl;
import io.security.springsecuritymaster.security.entrypoint.RestAuthenticationEntryPoint;
import io.security.springsecuritymaster.security.filters.CustomAuthorizationFilter;
import io.security.springsecuritymaster.security.handler.FormAccessDeniedHandler;
import io.security.springsecuritymaster.security.handler.FormAuthenticationFailureHandler;
import io.security.springsecuritymaster.security.handler.FormAuthenticationSuccessHandler;
import io.security.springsecuritymaster.security.handler.RestAccessDeniedHandler;
import io.security.springsecuritymaster.security.handler.RestAuthenticationFailureHandler;
import io.security.springsecuritymaster.security.handler.RestAuthenticationSuccessHandler;
import io.security.springsecuritymaster.security.manager.CustomDynamicAuthorizationManager;
import io.security.springsecuritymaster.security.provider.FormAuthenticationProvider;
import io.security.springsecuritymaster.security.provider.RestAuthenticationProvider;
import jakarta.servlet.Filter;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final FormAuthenticationProvider formAuthenticationProvider;
    private final RestAuthenticationProvider restAuthenticationProvider;
    private final AuthenticationDetailsSource<HttpServletRequest, WebAuthenticationDetails> authenticationDetailsSource;
    private final FormAuthenticationSuccessHandler formSuccessHandler;
    private final FormAuthenticationFailureHandler formFailureHandler;
    private final RestAuthenticationSuccessHandler restSuccessHandler;
    private final RestAuthenticationFailureHandler restFailureHandler;
//    private final AuthorizationManager<RequestAuthorizationContext> authorizationManager;
    private final AuthorizationManager<HttpServletRequest> authorizationManager;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(auth -> auth
//                        .anyRequest().access(authorizationManager))
                        .anyRequest().permitAll())
                .formLogin(form -> form
                        .loginPage("/login").permitAll() //커스텀 로그인 페이지
                        .authenticationDetailsSource(authenticationDetailsSource)
                        .successHandler(formSuccessHandler)
                        .failureHandler(formFailureHandler)
                )
                .authenticationProvider(formAuthenticationProvider)
                .exceptionHandling(exception -> exception
                        .accessDeniedHandler(new FormAccessDeniedHandler("/denied"))
                )
                .addFilterAfter(customAuthorizationFilter(), ExceptionTranslationFilter.class)
        ;

        return http.build();
    }

    private CustomAuthorizationFilter customAuthorizationFilter() {
        return new CustomAuthorizationFilter(authorizationManager);
    }

    @Bean
    @Order(1)
    public SecurityFilterChain restSecurityFilterChain(HttpSecurity http) throws Exception {

        AuthenticationManagerBuilder managerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
        managerBuilder.authenticationProvider(restAuthenticationProvider);
        AuthenticationManager authenticationManager = managerBuilder.build();

        http
                .securityMatcher("/api/**")
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/css/**", "/js/**", "/images/**", "/webjars/**", "/favicon.*", "/*/icon-*").permitAll() //정적 자원 관리
                        .requestMatchers("/api", "/api/login").permitAll()
                        .requestMatchers("/api/user").hasRole("USER")
                        .requestMatchers("/api/manager").hasRole("MANAGER")
                        .requestMatchers("/api/admin").hasRole("ADMIN")
                        .anyRequest().authenticated()
                )
//                .csrf(AbstractHttpConfigurer::disable)
                .authenticationManager(authenticationManager)
                .exceptionHandling(
                        exception -> exception
                        .authenticationEntryPoint(new RestAuthenticationEntryPoint())
                        .accessDeniedHandler(new RestAccessDeniedHandler())
                )
                .with(
                        new RestApiDsl<>(), restDsl -> restDsl
                        .restSuccessHandler(restSuccessHandler)
                        .restFailureHandler(restFailureHandler)
                        .loginPage("/api/login")
                        .loginProcessingUrl("/api/login")
                )
        ;

        return http.build();
    }
}
