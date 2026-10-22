package fr.supdevinci.argus.clients.epss;

import java.util.List;

/**
 * Réponse de l'API EPSS de FIRST.
 * Seule la liste des scores est conservée. Les métadonnées de pagination sont ignorées.
 *
 * @param data scores des CVE demandées
 */
public record EpssResponse(List<EpssScoreResponse> data) {
}
