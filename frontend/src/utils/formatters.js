/**
 * Les dates de l'API sont en UTC sans fuseau explicite. On ajoute "Z" pour que
 * le navigateur les interprète en UTC puis les affiche à l'heure locale.
 */
function parseUtcDate(value) {
  return new Date(value.endsWith('Z') ? value : `${value}Z`)
}

export function formatDate(value) {
  if (!value) return '-'
  return new Intl.DateTimeFormat('fr-FR', { dateStyle: 'medium' }).format(parseUtcDate(value))
}

export function formatDateTime(value) {
  if (!value) return '-'
  return new Intl.DateTimeFormat('fr-FR', { dateStyle: 'medium', timeStyle: 'short' }).format(parseUtcDate(value))
}

/**
 * Les dates KEV n'ont pas d'heure : elles sont affichées telles quelles, sans conversion de fuseau.
 */
export function formatLocalDate(value) {
  if (!value) return '-'
  const [year, month, day] = value.split('-')
  return new Intl.DateTimeFormat('fr-FR', { dateStyle: 'medium' }).format(new Date(year, month - 1, day))
}

/**
 * Score CVSS avec une décimale, au format français (9,8).
 */
export function formatScore(value) {
  return new Intl.NumberFormat('fr-FR', { minimumFractionDigits: 1, maximumFractionDigits: 1 }).format(value)
}

/**
 * Probabilité EPSS. Les valeurs trop petites pour être affichées s'écrivent "< 0,1 %"
 * au lieu de "0,0 %", qui laisserait croire à une probabilité nulle.
 */
export function formatProbability(value, fractionDigits = 1) {
  if (value === null || value === undefined) return '-'
  const smallestDisplayable = 10 ** -(fractionDigits + 2)
  if (value > 0 && value < smallestDisplayable) {
    return `< ${formatPercent(smallestDisplayable, fractionDigits)}`
  }
  return formatPercent(value, fractionDigits)
}

export function formatPercent(value, fractionDigits = 1) {
  if (value === null || value === undefined) return '-'
  return new Intl.NumberFormat('fr-FR', {
    style: 'percent',
    minimumFractionDigits: fractionDigits,
    maximumFractionDigits: fractionDigits,
  }).format(value)
}
