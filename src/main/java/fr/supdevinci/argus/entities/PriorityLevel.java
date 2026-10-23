package fr.supdevinci.argus.entities;

/**
 * Niveau de priorité déduit du score sur 100.
 * Les niveaux sont déclarés du plus élevé au plus faible.
 */
public enum PriorityLevel {

    CRITICAL(70),
    HIGH(45),
    MEDIUM(25),
    LOW(0);

    private final int minimumScore;

    PriorityLevel(int minimumScore) {
        this.minimumScore = minimumScore;
    }

    public int getMinimumScore() {
        return minimumScore;
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
