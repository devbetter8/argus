package fr.supdevinci.argus.clients.epss;

import java.time.LocalDate;

/**
 * Score EPSS d'une CVE.
 * L'API renvoie les nombres sous forme de texte ("0.999990000"). Jackson les convertit en double.
 *
 * @param cve identifiant CVE
 * @param epss probabilité d'exploitation dans les 30 jours, entre 0 et 1
 * @param percentile position du score parmi toutes les CVE, entre 0 et 1
 * @param date date de calcul du score
 */
public record EpssScoreResponse(
        String cve,
        double epss,
        double percentile,
        LocalDate date
) {
}
