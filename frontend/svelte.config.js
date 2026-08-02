import adapterStatic from "@sveltejs/adapter-static";

export default {
    kit: {
        adapter: adapterStatic(),
        paths: {
            base: ""
        }
    }
};
