<script setup>
import { computed } from 'vue'
import { PRIORITY_LEVELS } from '../utils/labels'

const props = defineProps({
  priority: { type: Object, required: true },
})

const level = computed(() => PRIORITY_LEVELS[props.priority.level])
</script>

<template>
  <span class="badge" :class="level.badgeClass">
    {{ level.label }} · {{ priority.score }}
  </span>
</template>
