package fr.supdevinci.argus.entities;

/**
 * Niveau de priorité déduit du score sur 100.
 * Les niveaux sont déclarés du plus élevé au plus faible.
 */
public enum PriorityLevel {

    CRITICAL(70, 100),
    HIGH(45, 69),
    MEDIUM(25, 44),
    LOW(0, 24);

    private final int minimumScore;
    private final int maximumScore;

    PriorityLevel(int minimumScore, int maximumScore) {
        this.minimumScore = minimumScore;
        this.maximumScore = maximumScore;
    }

    public int getMinimumScore() {
        return minimumScore;
    }

    public int getMaximumScore() {
        return maximumScore;
    }

    /**
     * Renvoie le premier niveau dont le score minimum est atteint.
     */
    public static PriorityLevel fromScore(int score) {
        for (PriorityLevel level : values()) {
            if (score >= level.minimumScore) {
                return level;
            }
        }
        return LOW;
    }
}
