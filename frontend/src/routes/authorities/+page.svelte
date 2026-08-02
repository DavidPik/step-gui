<script>
    import { apiGet } from "$lib/api";

    let authorities = [];

    apiGet("authorities").then(data => {
        authorities = data;
    });
</script>

<h1>Authorities</h1>

{#if authorities.length === 0}
    <p>No authorities found.</p>
{:else}
    <ul>
        {#each authorities as a}
            <li>{a.name} ({a.type})</li>
        {/each}
    </ul>
{/if}
