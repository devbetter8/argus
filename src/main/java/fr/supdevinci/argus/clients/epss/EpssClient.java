package fr.supdevinci.argus.clients.epss;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.util.ArrayList;
import java.util.List;

/**
 * Client HTTP de l'API EPSS (Exploit Prediction Scoring System) de FIRST.
 * L'API est publique et sans clé.
 */
@Component
public class EpssClient {

    /**
     * Nombre de CVE envoyées par requête.
     * Les identifiants passent dans l'URL. Un lot de 100 garde une URL de taille raisonnable.
     */
    static final int BATCH_SIZE = 100;

    private final RestClient restClient;

    public EpssClient(RestClient.Builder restClientBuilder, @Value("${argus.epss.url}") String epssUrl) {
        this.restClient = restClientBuilder.baseUrl(epssUrl).build();
    }

    /**
     * Récupère les scores EPSS des CVE demandées, par lots de {@value #BATCH_SIZE}.
     * Une CVE inconnue de l'API est simplement absente du résultat.
     * Une erreur HTTP lève une {@link org.springframework.web.client.RestClientResponseException}.
     */
    public List<EpssScoreResponse> fetchScores(List<String> cveIds) {
        List<EpssScoreResponse> scores = new ArrayList<>();

        for (int start = 0; start < cveIds.size(); start += BATCH_SIZE) {
            List<String> batch = cveIds.subList(start, Math.min(start + BATCH_SIZE, cveIds.size()));
            scores.addAll(fetchBatch(batch));
        }

        return scores;
    }

    private List<EpssScoreResponse> fetchBatch(List<String> batch) {
        EpssResponse response = restClient.get()
                .uri(uriBuilder -> uriBuilder
                        .queryParam("cve", String.join(",", batch))
                        // Sans ce paramètre, l'API limite la réponse à 100 résultats.
                        .queryParam("limit", batch.size())
                        .build())
                .retrieve()
                .body(EpssResponse.class);

        return response == null ? List.of() : response.data();
    }
}
