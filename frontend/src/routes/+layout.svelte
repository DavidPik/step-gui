<script>
    export let data;
</script>

<nav class="nav">
    <a href="/">Dashboard</a>
    <a href="/authorities">Authorities</a>
    <a href="/policies">Policies</a>
    <a href="/provisioners">Provisioners</a>
    <a href="/certificates">Certificates</a>
    <a href="/users">Users</a>
    <a href="/audit">Audit</a>
</nav>

<main>
    <slot />
</main>

<style>
    .nav {
        display: flex;
        gap: 1rem;
        padding: 1rem;
        background: #f0f0f0;
    }
    main {
        padding: 1rem;
    }
</style>
