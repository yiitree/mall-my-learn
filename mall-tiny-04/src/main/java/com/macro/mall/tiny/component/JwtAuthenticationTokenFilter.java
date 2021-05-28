package com.macro.mall.tiny.component;

import com.macro.mall.tiny.common.utils.JwtTokenUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * JWT登录授权过滤器
 * 在用户名和密码校验前添加的过滤器，如果有jwt的token，会自行根据token信息进行登录。
 * Created by macro on 2018/4/26.
 */
public class JwtAuthenticationTokenFilter extends OncePerRequestFilter {
    private static final Logger LOGGER = LoggerFactory.getLogger(JwtAuthenticationTokenFilter.class);
    @Autowired
    private UserDetailsService userDetailsService;
    @Autowired
    private JwtTokenUtil jwtTokenUtil;
    @Value("${jwt.tokenHeader}")
    private String tokenHeader;
    @Value("${jwt.tokenHead}")
    private String tokenHead;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {

        // Authorization:BearereyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJhZG1pbiIsImNyZWF0ZWQiOjE2MjIxNjg3MDc4NDgsImV4cCI6MTYyMjc3MzUwN30.8U0SrBLFMP-ahcDO6efNjnIc-9G39ggRZ-9nDdt5WwGb5lEschFJam8SwcyxDZYg8-BA74DcNtoEP6V7Y5OT5g
        String authHeader = request.getHeader(this.tokenHeader);
        if (authHeader != null && authHeader.startsWith(this.tokenHead)) {
            // The part after "Bearer "
            String authToken = authHeader.substring(this.tokenHead.length());
            // 从token中获取用户名
            String username = jwtTokenUtil.getUserNameFromToken(authToken);
            LOGGER.info("checking username:{}", username);
            // token中用户名存在，并且登录信息不存在
            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                // 根据用户名得到 用户 + 权限信息
                UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);
                // 验证token是否有效 --- token中保存着失效时间
                if (jwtTokenUtil.validateToken(authToken, userDetails)) {
                    // 把用户信息封装到UsernamePasswordAuthenticationToken，提取权限信息到
                    UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                    // 设置当前登录人员的远程地址等细节
                    authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    LOGGER.info("authenticated user:{}", username);
                    // 把认证信息保存在Security上下文中
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            }
        }
        chain.doFilter(request, response);
    }
}
