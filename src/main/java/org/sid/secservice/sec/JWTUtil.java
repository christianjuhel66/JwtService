package org.sid.secservice.sec;

public class JWTUtil {
    public static final String SECRET= "mySecret1234";
    public static final String AUTH_HEADER= "Authorization";
    public static final String PREFIX= "Bearer ";
    public static final long EXPIRE_ACCESS_TOKEN =120000; //2*60*1000 pour avoir 2 minutes en millisecondes
    public static final long EXPIRE_REFRESH_TOKEN =  900000  ;//15*60*1000 = 15 minutes
}
