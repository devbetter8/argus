package fr.supdevinci.argus.clients.nvd;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;

/**
 * Configuration du client NVD, lue depuis les propriétés "argus.nvd.*".
 *
 * @param url URL de l'API CVE 2.0
 * @param apiKey clé d'API personnelle
 * @param requestDelay pause entre deux requêtes, pour respecter la limite de débit
 */
@Validated
@ConfigurationProperties("argus.nvd")
public record NvdProperties(
        @NotBlank
        String url,
        @NotBlank
        String apiKey,
        @NotNull
        Duration requestDelay
) {
}
