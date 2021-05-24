package tech.getarrays.employeemanager.security;

public interface SecurityConstants {
    public final String HEADER = "Authorization";
    public final String PREFIX = "Bearer:";
    public final String SECRET = "Thereis No more security that the one We've made since 2021. We will make sure of that, make no mistake";
    public final String AUTHORITIES = "authorities";

    // Token expires very quickly, as any request asks for a token each time
    public final long TOKEN_EXPIRATION_TIME = 60000;

}
