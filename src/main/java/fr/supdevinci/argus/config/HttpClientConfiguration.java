package fr.supdevinci.argus.config;

import org.springframework.boot.http.client.ClientHttpRequestFactoryBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.net.http.HttpClient;

/**
 * Configuration commune des clients HTTP vers les APIs externes.
 */
@Configuration(proxyBeanMethods = false)
public class HttpClientConfiguration {

    /**
     * Force HTTP/1.1 au lieu de HTTP/2.
     * Le serveur de la NVD interrompt régulièrement les réponses HTTP/2 en cours de transfert
     * (erreur RST_STREAM). Les délais maximum définis dans application.yaml restent appliqués.
     */
    @Bean
    ClientHttpRequestFactoryBuilder<?> clientHttpRequestFactoryBuilder() {
        return ClientHttpRequestFactoryBuilder.jdk()
                .withHttpClientCustomizer(builder -> builder.version(HttpClient.Version.HTTP_1_1));
    }
}
