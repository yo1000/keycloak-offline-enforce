package com.yo1000.keycloak.client.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.endpoint.DefaultRefreshTokenTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2RefreshTokenGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.oauth2.core.http.converter.OAuth2ErrorHttpMessageConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

@SpringBootApplication
public class DemoApplication {
    public static void main(String[] args) {
        SpringApplication.run(DemoApplication.class, args);
    }

    @Configuration
    @EnableWebSecurity
    public static class SecurityConfig {
        @Bean
        public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
            httpSecurity
                    .authorizeHttpRequests(registry -> registry
                            .mvcMatchers("/**").authenticated()
                            .anyRequest().permitAll())
                    .oauth2Login(Customizer.withDefaults())
                    .logout(configurer -> configurer
                            .logoutUrl("/logout")
                            .logoutSuccessUrl("/"));

            return httpSecurity.build();
        }

        @Bean
        public OAuth2AuthorizedClientManager authorizedClientManager(
                ClientRegistrationRepository clientRegistrationRepository,
                OAuth2AuthorizedClientRepository authorizedClientRepository
        ) {
            DefaultOAuth2AuthorizedClientManager authorizedClientManager = new DefaultOAuth2AuthorizedClientManager(
                    clientRegistrationRepository, authorizedClientRepository);

            authorizedClientManager.setAuthorizedClientProvider(OAuth2AuthorizedClientProviderBuilder
                    .builder()
                    .clientCredentials()
                    .build());

            return authorizedClientManager;
        }
    }

    @RestController
    @RequestMapping("/")
    public static class ClientController {
        private final OAuth2AuthorizedClientService authorizedClientService;
        private final DefaultRefreshTokenTokenResponseClient tokenResponseClient;


        public ClientController(
                OAuth2AuthorizedClientService authorizedClientService,
                RestTemplateBuilder restTemplateBuilder
        ) {
            this.authorizedClientService = authorizedClientService;
            this.tokenResponseClient = new DefaultRefreshTokenTokenResponseClient();

            RestTemplate restTemplate = restTemplateBuilder
                    .messageConverters(
                            new OAuth2AccessTokenResponseHttpMessageConverter(),
                            new OAuth2ErrorHttpMessageConverter(),
                            new FormHttpMessageConverter())
                    .build();

            tokenResponseClient.setRestOperations(restTemplate);
        }

        @GetMapping("/accessToken")
        public String getAccessToken(
                OAuth2AuthenticationToken authentication
        ) {
            OAuth2AuthorizedClient currentAuthorizedClient = authorizedClientService.loadAuthorizedClient(
                    authentication.getAuthorizedClientRegistrationId(),
                    authentication.getName()
            );

            return currentAuthorizedClient.getAccessToken().getTokenValue();
        }

        @GetMapping("/refreshToken")
        public String getRefreshToken(
                OAuth2AuthenticationToken authentication
        ) {
            OAuth2AuthorizedClient currentAuthorizedClient = authorizedClientService.loadAuthorizedClient(
                    authentication.getAuthorizedClientRegistrationId(),
                    authentication.getName()
            );

            return currentAuthorizedClient.getRefreshToken().getTokenValue();
        }

        @GetMapping("/refreshToken/refresh")
        public String getRefreshTokenRefresh(
                OAuth2AuthenticationToken authentication
        ) {
            OAuth2AuthorizedClient currentAuthorizedClient = authorizedClientService.loadAuthorizedClient(
                    authentication.getAuthorizedClientRegistrationId(),
                    authentication.getName()
            );

            ClientRegistration clientRegistration = currentAuthorizedClient.getClientRegistration();

            OAuth2AccessTokenResponse refreshedTokenResponse = tokenResponseClient.getTokenResponse(
                    new OAuth2RefreshTokenGrantRequest(
                            clientRegistration,
                            currentAuthorizedClient.getAccessToken(),
                            currentAuthorizedClient.getRefreshToken()
                    )
            );

            authorizedClientService.removeAuthorizedClient(
                    currentAuthorizedClient.getClientRegistration().getRegistrationId(),
                    currentAuthorizedClient.getPrincipalName()
            );

            OAuth2AuthorizedClient refreshedAuthorizedClient = new OAuth2AuthorizedClient(
                    clientRegistration,
                    authentication.getName(),
                    refreshedTokenResponse.getAccessToken(),
                    refreshedTokenResponse.getRefreshToken()
            );

            authorizedClientService.saveAuthorizedClient(refreshedAuthorizedClient, authentication);

            return getRefreshToken(authentication);
        }
    }
}
