export async function apiGet(path: string) {
    const res = await fetch(`/api/${path}`);
    if (!res.ok) {
        throw new Error(`API error: ${res.status}`);
    }
    return await res.json();
}

export async function apiPost(path: string, body: any) {
    const res = await fetch(`/api/${path}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
    });
    if (!res.ok) {
        throw new Error(`API error: ${res.status}`);
    }
    return await res.json();
}
