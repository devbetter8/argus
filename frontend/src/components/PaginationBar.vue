<script setup>
const props = defineProps({
  page: { type: Object, required: true },
})

const emit = defineEmits(['change'])

function goTo(pageNumber) {
  if (pageNumber >= 0 && pageNumber < props.page.totalPages) {
    emit('change', pageNumber)
  }
}
</script>

<template>
  <nav v-if="page.totalPages > 1" class="d-flex align-items-center justify-content-between" aria-label="Pagination">
    <span class="text-body-secondary small">
      Page {{ page.number + 1 }} sur {{ page.totalPages }}
    </span>
    <ul class="pagination pagination-sm mb-0">
      <li class="page-item" :class="{ disabled: page.number === 0 }">
        <button class="page-link" @click="goTo(page.number - 1)">Précédente</button>
      </li>
      <li class="page-item" :class="{ disabled: page.number >= page.totalPages - 1 }">
        <button class="page-link" @click="goTo(page.number + 1)">Suivante</button>
      </li>
    </ul>
  </nav>
</template>
