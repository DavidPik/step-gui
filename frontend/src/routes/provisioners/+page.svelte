<script>
    import { apiGet } from "$lib/api";

    let provisioners = [];

    apiGet("provisioners").then(data => {
        provisioners = data;
    });
</script>

<h1>Provisioners</h1>

{#if provisioners.length === 0}
    <p>No provisioners found.</p>
{:else}
    <ul>
        {#each provisioners as p}
            <li>{p.name} ({p.type})</li>
        {/each}
    </ul>
{/if}
