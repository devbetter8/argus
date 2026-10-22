package fr.supdevinci.argus.clients.kev;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

/**
 * Client HTTP du catalogue KEV (Known Exploited Vulnerabilities) de la CISA.
 * Le catalogue est un fichier JSON unique, sans clé d'API.
 */
@Component
public class KevClient {

    private final RestClient restClient;

    public KevClient(RestClient.Builder restClientBuilder, @Value("${argus.kev.url}") String kevUrl) {
        this.restClient = restClientBuilder.baseUrl(kevUrl).build();
    }

    /**
     * Télécharge le catalogue complet.
     * Une erreur HTTP lève une {@link org.springframework.web.client.RestClientResponseException}.
     */
    public KevCatalogResponse fetchCatalog() {
        return restClient.get()
                .retrieve()
                .body(KevCatalogResponse.class);
    }
}
