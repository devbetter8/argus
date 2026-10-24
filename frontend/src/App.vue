<template>
  <nav class="navbar bg-dark" data-bs-theme="dark">
    <div class="container">
      <RouterLink class="navbar-brand fw-semibold" :to="{ name: 'vulnerabilities' }">Argus</RouterLink>
      <span class="navbar-text small d-none d-sm-inline">Priorisation des vulnérabilités</span>
    </div>
  </nav>

  <main class="container py-4">
    <RouterView />
  </main>
</template>
