import { writable } from "svelte/store";

export const user = writable(null);
export const loading = writable(false);
export const error = writable(null);
