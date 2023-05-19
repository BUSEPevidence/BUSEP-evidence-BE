package com.pki.example.auth.Interceptor;
import com.pki.example.auth.AuthenticationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Component
public class TokenInterceptor implements HandlerInterceptor {

    private final AuthenticationService authenticationService;

    public TokenInterceptor(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        // This method is called before the actual handler method is invoked
        // Implement your logic here for pre-processing the request
        var refreshToken = request.getHeader("refreshToken");
        var authorizationString = request.getHeader("Authorization");
        var token = "";
        if(authorizationString != null)
            token = authorizationString.substring(7);
        if(refreshToken != null) {
            var tokenR = this.authenticationService.generateNewAccessToken(refreshToken,token);
            if(tokenR != "") {
                response.setHeader("tokenR", tokenR);
            }
        }
        return true; // Return true to allow the request to continue, or false to stop further processing
    }

    @Override
    public void postHandle(HttpServletRequest request, HttpServletResponse response, Object handler, ModelAndView modelAndView) throws Exception {
        // This method is called after the handler method is invoked, but before the view is rendered (if applicable)
        // Implement your logic here for post-processing the request or modifying the response
    }

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) throws Exception {
        // This method is called after the view is rendered (if applicable) or when an exception occurs
        // Implement your logic here for any cleanup or additional processing
    }
}
