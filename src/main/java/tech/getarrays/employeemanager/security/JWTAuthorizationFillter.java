package tech.getarrays.employeemanager.security;

import io.jsonwebtoken.*;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.stream.Collectors;

public class JWTAuthorizationFillter extends OncePerRequestFilter implements SecurityConstants {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try {
            if (checkJWTToken(request)) {
                Claims claims = getTokenClaims(request);
                if (claims.get(AUTHORITIES) != null) {
                    setUpSpringAuthentication(claims);
                } else {
                    SecurityContextHolder.clearContext();
                }
            } else {
                SecurityContextHolder.clearContext();
            }
            filterChain.doFilter(request, response);
        } catch (ExpiredJwtException | UnsupportedJwtException | MalformedJwtException e) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.sendError(HttpServletResponse.SC_FORBIDDEN, e.getMessage());
            return;
        }
    }

    /**
     * Registers the user and authorization in the security context.
     * @param claims User request's claims.
     */
    private void setUpSpringAuthentication(Claims claims) {
        List<String> authorities = (List<String>) claims.get(AUTHORITIES);
        UsernamePasswordAuthenticationToken auth =
                new UsernamePasswordAuthenticationToken(claims.getSubject(), null,
                        authorities.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList()));
        SecurityContextHolder.getContext().setAuthentication(auth);
    }

    /**
     * Gets token claims.
     * @param request Originating requests.
     * @return Claims found.
     */
    private Claims getTokenClaims(HttpServletRequest request) {
        String jwtToken = request.getHeader(HEADER).replace(PREFIX, "");
        return Jwts.parserBuilder().setSigningKey(SECRET.getBytes(StandardCharsets.UTF_8))
                .build()
                .parseClaimsJws(jwtToken).getBody();

    }

    /**
     * Validates if Authorization header is present and has a bearer.
     * @param request Originating request.
     * @return True if the request conforms to expected tokenized request.
     */
    private boolean checkJWTToken(HttpServletRequest request) {
        String authenticationHeader = request.getHeader(HEADER);
        if (authenticationHeader == null || !authenticationHeader.startsWith(PREFIX)) {
            return false;
        }
        return true;
    }
}
