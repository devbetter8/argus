package fr.supdevinci.argus.services;

import fr.supdevinci.argus.clients.nvd.NvdCvePageResponse.CvssData;
import fr.supdevinci.argus.clients.nvd.NvdCvePageResponse.CvssMetric;
import fr.supdevinci.argus.clients.nvd.NvdCvePageResponse.Metrics;
import fr.supdevinci.argus.entities.CvssScore;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test unitaire simple : aucune dépendance à Spring ni à la base.
 */
class CvssScoreSelectorTest {

    @Test
    void select_prefersMostRecentCvssVersion() {
        Metrics metrics = new Metrics(
                List.of(metric("Secondary", "4.0", 9.3)),
                List.of(metric("Primary", "3.1", 9.8)),
                null,
                null);

        CvssScore score = CvssScoreSelector.select(metrics);

        assertThat(score.version()).isEqualTo("4.0");
        assertThat(score.baseScore()).isEqualTo(9.3);
    }

    @Test
    void select_prefersNvdScoreWithinSameVersion() {
        Metrics metrics = new Metrics(
                null,
                List.of(metric("Secondary", "3.1", 7.5), metric("Primary", "3.1", 9.8)),
                null,
                null);

        assertThat(CvssScoreSelector.select(metrics).baseScore()).isEqualTo(9.8);
    }

    @Test
    void select_usesFirstScoreWhenNoNvdScore() {
        Metrics metrics = new Metrics(
                null,
                List.of(metric("Secondary", "3.1", 7.5), metric("Secondary", "3.1", 8.1)),
                null,
                null);

        assertThat(CvssScoreSelector.select(metrics).baseScore()).isEqualTo(7.5);
    }

    @Test
    void select_fallsBackToCvssV2() {
        Metrics metrics = new Metrics(List.of(), null, null, List.of(metric("Primary", "2.0", 9.3)));

        assertThat(CvssScoreSelector.select(metrics).version()).isEqualTo("2.0");
    }

    @Test
    void select_returnsNullWithoutAnyScore() {
        assertThat(CvssScoreSelector.select(new Metrics(null, null, null, null))).isNull();
        assertThat(CvssScoreSelector.select(null)).isNull();
    }

    private static CvssMetric metric(String type, String version, double baseScore) {
        return new CvssMetric("source@test", type, new CvssData(version, "CVSS:" + version, baseScore, "HIGH"));
    }
}
