package fr.supdevinci.argus.services;

import fr.supdevinci.argus.entities.CvssScore;
import fr.supdevinci.argus.entities.PriorityLevel;
import fr.supdevinci.argus.entities.Vulnerability;
import org.junit.jupiter.api.Test;

import java.time.LocalDate;
import java.time.LocalDateTime;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Vérifie la formule avec les exemples présentés lors de sa conception.
 */
class PriorityCalculatorTest {

    @Test
    void calculate_exploitedByRansomware_reachesMaximum() {
        Vulnerability log4shell = vulnerability(10.0, 1.0);
        log4shell.markAsKnownExploited(LocalDate.of(2021, 12, 10), LocalDate.of(2021, 12, 24), true);

        assertThat(PriorityCalculator.calculate(log4shell)).isEqualTo(100);
    }

    @Test
    void calculate_knownExploited_addsBonus() {
        Vulnerability exploited = vulnerability(7.8, 0.95);
        exploited.markAsKnownExploited(LocalDate.of(2026, 10, 1), LocalDate.of(2026, 10, 22), false);

        // 27,3 + 35 (exploitation constatée) + 20 = 82,3
        assertThat(PriorityCalculator.calculate(exploited)).isEqualTo(82);
    }

    @Test
    void calculate_knownExploitedWithLowEpss_isCritical() {
        // Cas réel : CVE ajoutée au catalogue KEV le jour même, EPSS pas encore à jour.
        Vulnerability justAddedToKev = vulnerability(9.4, 0.45586);
        justAddedToKev.markAsKnownExploited(LocalDate.of(2026, 10, 23), LocalDate.of(2026, 11, 13), false);

        // 32,9 + 35 + 20 = 87,9
        int score = PriorityCalculator.calculate(justAddedToKev);

        assertThat(score).isEqualTo(88);
        assertThat(PriorityLevel.fromScore(score)).isEqualTo(PriorityLevel.CRITICAL);
    }

    @Test
    void calculate_likelyExploitation_outranksHigherCvss() {
        int likely = PriorityCalculator.calculate(vulnerability(7.5, 0.98));
        int unlikely = PriorityCalculator.calculate(vulnerability(9.8, 0.05));

        assertThat(likely).isEqualTo(61);
        assertThat(unlikely).isEqualTo(36);
        assertThat(likely).isGreaterThan(unlikely);
    }

    @Test
    void calculate_mediumAndUnlikely_staysLow() {
        assertThat(PriorityCalculator.calculate(vulnerability(5.3, 0.20))).isEqualTo(26);
    }

    @Test
    void calculate_withMissingData_usesNeutralValues() {
        Vulnerability notAnalyzed = new Vulnerability("CVE-2026-0001");
        notAnalyzed.updateNvdData("Description", LocalDateTime.now(), LocalDateTime.now(), "Received", null);

        assertThat(PriorityCalculator.calculate(notAnalyzed)).isEqualTo(35);
    }

    private static Vulnerability vulnerability(double cvssScore, double epssPercentile) {
        Vulnerability vulnerability = new Vulnerability("CVE-2026-0001");
        vulnerability.updateNvdData("Description", LocalDateTime.now(), LocalDateTime.now(), "Analyzed",
                new CvssScore("3.1", cvssScore, "HIGH", "CVSS:3.1/AV:N"));
        vulnerability.updateEpss(0.1, epssPercentile);
        return vulnerability;
    }
}
