package com.coocon.admin.filter;

import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;

import javax.servlet.*;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.UUID;

@WebFilter
@Slf4j
public class LoggingFilter implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        MDC.put("traceId", UUID.randomUUID().toString());

        log.info("###### HTTP REQUEST INPUT - {}) ######",req.getRequestURI());
        req.getHeaderNames().asIterator().forEachRemaining(
                header ->
                        log.debug("HTTP Header [{} : {}]",header, req.getHeader(header))
        );

        chain.doFilter(request, response);
        log.info("###### HTTP RESPONSE OUTPUT status {} ######", res.getStatus());
    }
}
