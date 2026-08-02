<script>
    import { apiGet } from "$lib/api";

    let policies = [];

    apiGet("policies").then(data => {
        policies = data;
    });
</script>

<h1>Policies</h1>

{#if policies.length === 0}
    <p>No policies found.</p>
{:else}
    <ul>
        {#each policies as p}
            <li>{p.name} (v{p.version})</li>
        {/each}
    </ul>
{/if}
