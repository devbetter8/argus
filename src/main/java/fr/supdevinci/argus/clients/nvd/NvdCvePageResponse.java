package fr.supdevinci.argus.clients.nvd;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Une page de résultats de l'API CVE 2.0 de la NVD.
 * Les records imbriqués reproduisent la structure du JSON. Seuls les champs utiles sont conservés.
 *
 * @param resultsPerPage nombre de résultats dans cette page
 * @param startIndex position du premier résultat de la page
 * @param totalResults nombre total de résultats pour la recherche
 * @param vulnerabilities vulnérabilités de la page
 */
public record NvdCvePageResponse(
        int resultsPerPage,
        int startIndex,
        int totalResults,
        List<Vulnerability> vulnerabilities
) {

    /**
     * Enveloppe d'une CVE dans le JSON.
     */
    public record Vulnerability(Cve cve) {
    }

    /**
     * Données d'une CVE. Les dates sont exprimées en UTC.
     *
     * @param id identifiant CVE
     * @param published date de publication
     * @param lastModified date de dernière modification
     * @param vulnStatus état de l'analyse NVD, par exemple "Analyzed" ou "Awaiting Analysis"
     * @param descriptions descriptions, une par langue
     * @param metrics scores CVSS, absents si la CVE n'a pas encore été évaluée
     */
    public record Cve(
            String id,
            LocalDateTime published,
            LocalDateTime lastModified,
            String vulnStatus,
            List<Description> descriptions,
            Metrics metrics
    ) {
    }

    /**
     * @param lang code de langue, par exemple "en"
     * @param value texte de la description
     */
    public record Description(String lang, String value) {
    }

    /**
     * Scores CVSS par version de la norme. Une liste est null si aucun score n'existe pour cette version.
     */
    public record Metrics(
            List<CvssMetric> cvssMetricV40,
            List<CvssMetric> cvssMetricV31,
            List<CvssMetric> cvssMetricV30,
            List<CvssMetric> cvssMetricV2
    ) {
    }

    /**
     * @param source organisme qui a calculé le score, par exemple "nvd@nist.gov"
     * @param type "Primary" pour le score de la NVD, "Secondary" pour celui d'un autre organisme
     * @param cvssData détail du score
     */
    public record CvssMetric(String source, String type, CvssData cvssData) {
    }

    /**
     * @param version version de la norme CVSS
     * @param vectorString vecteur CVSS complet
     * @param baseScore score de base, entre 0 et 10
     * @param baseSeverity niveau de gravité, absent en CVSS 2.0
     */
    public record CvssData(String version, String vectorString, double baseScore, String baseSeverity) {
    }
}
