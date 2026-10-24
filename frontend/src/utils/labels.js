/**
 * Libellés et couleurs Bootstrap des niveaux de priorité renvoyés par l'API.
 * L'ordre suit celui de l'API, du plus urgent au moins urgent.
 */
export const PRIORITY_LEVELS = {
  CRITICAL: { label: 'Critique', badgeClass: 'text-bg-danger' },
  HIGH: { label: 'Élevée', badgeClass: 'text-bg-warning' },
  MEDIUM: { label: 'Moyenne', badgeClass: 'text-bg-primary' },
  LOW: { label: 'Faible', badgeClass: 'text-bg-secondary' },
}

/**
 * Libellés français des niveaux de gravité CVSS renvoyés par la NVD.
 */
export const CVSS_SEVERITIES = {
  CRITICAL: 'Critique',
  HIGH: 'Élevée',
  MEDIUM: 'Moyenne',
  LOW: 'Faible',
  NONE: 'Aucune',
}
