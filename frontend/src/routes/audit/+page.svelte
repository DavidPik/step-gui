<script>
    import { apiGet } from "$lib/api";

    let audit = [];

    apiGet("audit").then(data => {
        audit = data;
    });
</script>

<h1>Audit Log</h1>

{#if audit.length === 0}
    <p>No audit entries.</p>
{:else}
    <ul>
        {#each audit as a}
            <li>{a.timestamp} — {a.action}</li>
        {/each}
    </ul>
{/if}
