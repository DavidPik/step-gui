<script>
    import { apiGet } from "$lib/api";

    let users = [];

    apiGet("users").then(data => {
        users = data;
    });
</script>

<h1>Users</h1>

{#if users.length === 0}
    <p>No users found.</p>
{:else}
    <ul>
        {#each users as u}
            <li>{u.username} — {u.status}</li>
        {/each}
    </ul>
{/if}
