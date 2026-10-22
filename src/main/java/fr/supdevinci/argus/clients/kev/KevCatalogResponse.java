package fr.supdevinci.argus.clients.kev;

import java.time.Instant;
import java.util.List;

/**
 * Catalogue KEV tel que renvoyé par la CISA.
 *
 * @param catalogVersion version du catalogue, sous la forme "2026.10.21"
 * @param dateReleased date de publication du catalogue
 * @param count nombre total de vulnérabilités
 * @param vulnerabilities vulnérabilités activement exploitées
 */
public record KevCatalogResponse(
        String catalogVersion,
        Instant dateReleased,
        int count,
        List<KevVulnerabilityResponse> vulnerabilities
) {
}
