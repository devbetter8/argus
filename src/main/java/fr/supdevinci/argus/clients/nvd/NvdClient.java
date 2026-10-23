package fr.supdevinci.argus.clients.nvd;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

/**
 * Client HTTP de l'API CVE 2.0 de la NVD (NIST).
 * Il parcourt automatiquement toutes les pages de résultats.
 */
@Component
@EnableConfigurationProperties(NvdProperties.class)
public class NvdClient {

    /** Nombre maximal de résultats par page autorisé par l'API. */
    static final int PAGE_SIZE = 2000;

    /** Écart maximal autorisé par l'API entre la date de début et la date de fin. */
    static final Duration MAX_DATE_RANGE = Duration.ofDays(120);

    private static final DateTimeFormatter NVD_DATE_FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS");

    private final RestClient restClient;
    private final Duration requestDelay;

    public NvdClient(RestClient.Builder restClientBuilder, NvdProperties properties) {
        this.restClient = restClientBuilder
                .baseUrl(properties.url())
                .defaultHeader("apiKey", properties.apiKey())
                .build();
        this.requestDelay = properties.requestDelay();
    }

    /**
     * Récupère les CVE publiées entre deux dates UTC.
     * Sert au premier chargement des données.
     */
    public List<NvdCvePageResponse.Cve> fetchPublishedBetween(LocalDateTime start, LocalDateTime end) {
        return fetchAllPages("pubStartDate", "pubEndDate", start, end);
    }

    /**
     * Récupère les CVE créées ou modifiées entre deux dates UTC.
     * Sert aux synchronisations suivantes.
     */
    public List<NvdCvePageResponse.Cve> fetchModifiedBetween(LocalDateTime start, LocalDateTime end) {
        return fetchAllPages("lastModStartDate", "lastModEndDate", start, end);
    }

    private List<NvdCvePageResponse.Cve> fetchAllPages(String startParam, String endParam, LocalDateTime start, LocalDateTime end) {
        checkDateRange(start, end);

        List<NvdCvePageResponse.Cve> cves = new ArrayList<>();
        int startIndex = 0;
        NvdCvePageResponse page;

        do {
            if (startIndex > 0) {
                waitBeforeNextRequest();
            }
            page = fetchPage(startParam, endParam, start, end, startIndex);
            page.vulnerabilities().forEach(vulnerability -> cves.add(vulnerability.cve()));
            startIndex += page.vulnerabilities().size();
            // On s'arrête aussi sur une page vide, pour ne jamais boucler indéfiniment.
        } while (!page.vulnerabilities().isEmpty() && startIndex < page.totalResults());

        return cves;
    }

    private NvdCvePageResponse fetchPage(String startParam, String endParam, LocalDateTime start, LocalDateTime end, int startIndex) {
        return restClient.get()
                .uri(uriBuilder -> uriBuilder
                        .queryParam(startParam, start.format(NVD_DATE_FORMAT))
                        .queryParam(endParam, end.format(NVD_DATE_FORMAT))
                        .queryParam("resultsPerPage", PAGE_SIZE)
                        .queryParam("startIndex", startIndex)
                        // Exclut les CVE rejetées (doublons, erreurs de déclaration).
                        .queryParam("noRejected")
                        .build())
                .retrieve()
                .body(NvdCvePageResponse.class);
    }

    private void checkDateRange(LocalDateTime start, LocalDateTime end) {
        if (end.isBefore(start)) {
            throw new IllegalArgumentException("La date de fin doit être postérieure à la date de début.");
        }
        if (Duration.between(start, end).compareTo(MAX_DATE_RANGE) > 0) {
            throw new IllegalArgumentException("L'API NVD n'accepte pas plus de 120 jours entre les deux dates.");
        }
    }

    private void waitBeforeNextRequest() {
        try {
            Thread.sleep(requestDelay);
        } catch (InterruptedException exception) {
            // On rétablit l'état d'interruption pour que l'appelant puisse le détecter.
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Synchronisation NVD interrompue.", exception);
        }
    }
}
