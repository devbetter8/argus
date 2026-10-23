package fr.supdevinci.argus.services;

import fr.supdevinci.argus.entities.Vulnerability;

/**
 * Calcule le score de priorité d'une vulnérabilité sur 100.
 * <p>
 * Formule :
 * <pre>
 * score = 35 × (CVSS / 10)
 *       + 35 × percentile EPSS
 *       + 20 si la faille est dans le catalogue KEV
 *       + 10 si elle est utilisée par des rançongiciels
 * </pre>
 * Gravité (CVSS) et probabilité (EPSS) ont le même poids, car un risque combine impact et probabilité.
 * Une exploitation constatée (KEV) ajoute un bonus, car elle est plus fiable qu'une prédiction.
 * <p>
 * Une donnée manquante prend une valeur neutre : une faille pas encore évaluée
 * ne doit pas paraître moins dangereuse qu'elle ne l'est peut-être.
 * <p>
 * Pour une faille du catalogue KEV, le percentile EPSS est remplacé par 1 :
 * EPSS prédit une exploitation or celle-ci est déjà constatée. EPSS met aussi
 * plusieurs jours à réagir après l'ajout d'une faille au catalogue.
 */
public final class PriorityCalculator {

    static final double CVSS_WEIGHT = 35;
    static final double EPSS_WEIGHT = 35;
    static final double KNOWN_EXPLOITED_BONUS = 20;
    static final double RANSOMWARE_BONUS = 10;

    static final double NEUTRAL_CVSS_SCORE = 5.0;
    static final double NEUTRAL_EPSS_PERCENTILE = 0.5;

    private static final double MAX_CVSS_SCORE = 10.0;
    private static final double MAX_EPSS_PERCENTILE = 1.0;

    private PriorityCalculator() {
    }

    public static int calculate(Vulnerability vulnerability) {
        double cvssScore = vulnerability.getCvss() == null
                ? NEUTRAL_CVSS_SCORE
                : vulnerability.getCvss().baseScore();
        double epssPercentile = epssPercentile(vulnerability);

        double score = CVSS_WEIGHT * (cvssScore / MAX_CVSS_SCORE)
                + EPSS_WEIGHT * epssPercentile;

        if (vulnerability.isKnownExploited()) {
            score += KNOWN_EXPLOITED_BONUS;
        }
        if (vulnerability.isKevRansomwareUse()) {
            score += RANSOMWARE_BONUS;
        }

        return (int) Math.round(score);
    }

    private static double epssPercentile(Vulnerability vulnerability) {
        if (vulnerability.isKnownExploited()) {
            return MAX_EPSS_PERCENTILE;
        }
        if (vulnerability.getEpssPercentile() == null) {
            return NEUTRAL_EPSS_PERCENTILE;
        }
        return vulnerability.getEpssPercentile();
    }
}
