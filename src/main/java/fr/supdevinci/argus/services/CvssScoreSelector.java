package fr.supdevinci.argus.services;

import fr.supdevinci.argus.clients.nvd.NvdCvePageResponse.CvssData;
import fr.supdevinci.argus.clients.nvd.NvdCvePageResponse.CvssMetric;
import fr.supdevinci.argus.clients.nvd.NvdCvePageResponse.Metrics;
import fr.supdevinci.argus.entities.CvssScore;

import java.util.List;
import java.util.stream.Stream;

/**
 * Choisit le score CVSS à retenir parmi ceux fournis par la NVD.
 * <p>
 * Règles :
 * <ol>
 *     <li>la version la plus récente de la norme est préférée (4.0, puis 3.1, 3.0 et 2.0) ;</li>
 *     <li>pour une même version, le score de la NVD ("Primary") est préféré à celui d'un autre organisme.</li>
 * </ol>
 */
public final class CvssScoreSelector {

    private static final String PRIMARY_SOURCE = "Primary";

    private CvssScoreSelector() {
    }

    /**
     * @return le score retenu ou null si la CVE n'a aucun score
     */
    public static CvssScore select(Metrics metrics) {
        if (metrics == null) {
            return null;
        }

        return Stream.of(metrics.cvssMetricV40(), metrics.cvssMetricV31(),
                        metrics.cvssMetricV30(), metrics.cvssMetricV2())
                .filter(cvssMetrics -> cvssMetrics != null && !cvssMetrics.isEmpty())
                .findFirst()
                .map(CvssScoreSelector::preferPrimary)
                .map(CvssScoreSelector::toCvssScore)
                .orElse(null);
    }

    private static CvssMetric preferPrimary(List<CvssMetric> cvssMetrics) {
        return cvssMetrics.stream()
                .filter(cvssMetric -> PRIMARY_SOURCE.equals(cvssMetric.type()))
                .findFirst()
                .orElse(cvssMetrics.getFirst());
    }

    private static CvssScore toCvssScore(CvssMetric cvssMetric) {
        CvssData data = cvssMetric.cvssData();
        return new CvssScore(data.version(), data.baseScore(), data.baseSeverity(), data.vectorString());
    }
}
