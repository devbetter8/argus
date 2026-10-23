package fr.supdevinci.argus.clients.nvd;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.core.retry.RetryListener;
import org.springframework.core.retry.RetryPolicy;
import org.springframework.core.retry.RetryTemplate;
import org.springframework.core.retry.Retryable;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

/**
 * Client HTTP de l'API CVE 2.0 de la NVD (NIST).
 * Il parcourt automatiquement toutes les pages de résultats et réessaie une page en cas d'échec temporaire.
 */
@Component
@EnableConfigurationProperties(NvdProperties.class)
public class NvdClient {

    private static final Logger log = LoggerFactory.getLogger(NvdClient.class);

    /**
     * Nombre de résultats par page. L'API accepte jusqu'à 2000, mais les grosses réponses
     * sont lentes et la NVD coupe parfois la connexion avant la fin du transfert.
     */
    static final int PAGE_SIZE = 500;

    /** Nombre de nouveaux essais pour une page, après le premier échec. */
    static final int MAX_RETRIES = 3;

    /** Écart maximal autorisé par l'API entre la date de début et la date de fin. */
    public static final Duration MAX_DATE_RANGE = Duration.ofDays(120);

    private static final DateTimeFormatter NVD_DATE_FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS");

    private final RestClient restClient;
    private final Duration requestDelay;
    private final RetryTemplate retryTemplate;

    public NvdClient(RestClient.Builder restClientBuilder, NvdProperties properties) {
        this.restClient = restClientBuilder
                .baseUrl(properties.url())
                .defaultHeader("apiKey", properties.apiKey())
                .build();
        this.requestDelay = properties.requestDelay();
        this.retryTemplate = createRetryTemplate(properties.requestDelay());
    }

    /**
     * Réessaie les erreurs temporaires : coupure réseau, réponse incomplète ou erreur 5xx.
     * Les erreurs 4xx (clé refusée, paramètre invalide) ne sont pas réessayées, car elles se reproduiraient.
     * Le délai double à chaque essai pour laisser le temps au serveur de se rétablir.
     */
    private static RetryTemplate createRetryTemplate(Duration initialDelay) {
        RetryPolicy retryPolicy = RetryPolicy.builder()
                .maxRetries(MAX_RETRIES)
                .delay(initialDelay)
                .multiplier(2)
                .includes(RestClientException.class)
                .excludes(HttpClientErrorException.class)
                .build();

        RetryTemplate retryTemplate = new RetryTemplate(retryPolicy);
        retryTemplate.setRetryListener(new RetryListener() {
            @Override
            public void onRetryFailure(RetryPolicy policy, Retryable<?> retryable, Throwable throwable) {
                log.warn("Échec d'une requête NVD, nouvel essai prévu : {}", throwable.getMessage());
            }
        });
        return retryTemplate;
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
            log.info("NVD : {} CVE récupérées sur {}.", startIndex, page.totalResults());
            // On s'arrête aussi sur une page vide, pour ne jamais boucler indéfiniment.
        } while (!page.vulnerabilities().isEmpty() && startIndex < page.totalResults());

        return cves;
    }

    private NvdCvePageResponse fetchPage(String startParam, String endParam, LocalDateTime start, LocalDateTime end, int startIndex) {
        return retryTemplate.invoke(() -> restClient.get()
                .uri(uriBuilder -> uriBuilder
                        .queryParam(startParam, start.format(NVD_DATE_FORMAT))
                        .queryParam(endParam, end.format(NVD_DATE_FORMAT))
                        .queryParam("resultsPerPage", PAGE_SIZE)
                        .queryParam("startIndex", startIndex)
                        // Exclut les CVE rejetées (doublons, erreurs de déclaration).
                        .queryParam("noRejected")
                        .build())
                .retrieve()
                .body(NvdCvePageResponse.class));
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
