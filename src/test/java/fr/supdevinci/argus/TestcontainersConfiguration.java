package fr.supdevinci.argus;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Bean;
import org.testcontainers.mysql.MySQLContainer;

/**
 * Démarre une base MySQL jetable dans Docker pour les tests.
 * Grâce à @ServiceConnection, Spring Boot s'y connecte sans configuration supplémentaire.
 */
@TestConfiguration(proxyBeanMethods = false)
public class TestcontainersConfiguration {

    @Bean
    @ServiceConnection
    MySQLContainer mysqlContainer() {
        // Même version que dans compose.yaml.
        return new MySQLContainer("mysql:8.4");
    }
}
