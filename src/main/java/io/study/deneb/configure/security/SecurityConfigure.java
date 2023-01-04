package io.study.deneb.configure.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configurers.provisioning.UserDetailsManagerConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;

import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfigure {

  @Bean
  public JdbcUserDetailsManager users(DataSource dataSource, PasswordEncoder passwordEncoder) {
    UserDetails user = User.builder()
      .username("deneb")
      .password(passwordEncoder.encode("1234"))
      .roles("admin")
      .build();

    JdbcUserDetailsManager jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);
    jdbcUserDetailsManager.createUser(user);
    return jdbcUserDetailsManager;
  }

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    return http
      .csrf(csrf -> csrf.ignoringRequestMatchers(antMatcher("/h2-console/**")))
      .authorizeHttpRequests(auth -> auth
        .requestMatchers(antMatcher("/h2-console/**")).permitAll()
        .anyRequest().authenticated()
      )
      .formLogin(withDefaults())
      .headers(headers -> headers.frameOptions().sameOrigin())
      .build();
  }

}
