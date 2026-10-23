package fr.supdevinci.argus.entities;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;

/**
 * Score CVSS retenu pour une vulnérabilité.
 * Ses colonnes sont stockées directement dans la table vulnerability.
 *
 * @param version version de la norme CVSS, par exemple "3.1"
 * @param baseScore score de base, entre 0 et 10
 * @param severity niveau de gravité, absent en CVSS 2.0
 * @param vector vecteur CVSS complet
 */
@Embeddable
public record CvssScore(
        @Column(name = "cvss_version") String version,
        @Column(name = "cvss_base_score") double baseScore,
        @Column(name = "cvss_severity") String severity,
        @Column(name = "cvss_vector") String vector
) {
}
