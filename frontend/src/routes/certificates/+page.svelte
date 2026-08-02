<script>
    import { apiGet } from "$lib/api";

    let certificates = [];

    apiGet("certificates").then(data => {
        certificates = data;
    });
</script>

<h1>Certificates</h1>

{#if certificates.length === 0}
    <p>No certificates found.</p>
{:else}
    <ul>
        {#each certificates as c}
            <li>{c.serial_number} — {c.status}</li>
        {/each}
    </ul>
{/if}
