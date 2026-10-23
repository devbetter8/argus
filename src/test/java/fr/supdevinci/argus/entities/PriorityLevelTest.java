package fr.supdevinci.argus.entities;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.assertj.core.api.Assertions.assertThat;

class PriorityLevelTest {

    @ParameterizedTest
    @CsvSource({
            "100, CRITICAL",
            "70, CRITICAL",
            "69, HIGH",
            "45, HIGH",
            "44, MEDIUM",
            "25, MEDIUM",
            "24, LOW",
            "0, LOW"
    })
    void fromScore_returnsLevelForEachThreshold(int score, PriorityLevel expectedLevel) {
        assertThat(PriorityLevel.fromScore(score)).isEqualTo(expectedLevel);
    }
}
