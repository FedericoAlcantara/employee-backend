package tech.getarrays.employeemanager.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.CorsConfigurer;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;

@EnableWebSecurity
@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .addFilterAfter(new JWTAuthorizationFillter(), UsernamePasswordAuthenticationFilter.class)
                .authorizeRequests()
                .antMatchers(HttpMethod.POST, "/user/login").permitAll()
                .anyRequest().authenticated();

        http.cors().configurationSource(request ->  {
            CorsConfiguration returnValue = new CorsConfiguration();
            returnValue.addAllowedOriginPattern("http://localhost:4200");
            returnValue.addAllowedMethod(HttpMethod.GET);
            returnValue.addAllowedMethod(HttpMethod.POST);
            returnValue.addAllowedMethod(HttpMethod.PUT);
            returnValue.addAllowedMethod(HttpMethod.DELETE);
            return returnValue.applyPermitDefaultValues();
        });
    }
}
