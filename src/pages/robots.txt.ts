import type { APIRoute } from "astro";

const robotsTxt = `
User-agent: *
Disallow: /_astro/

Sitemap: https://medoabd.github.io/MyBlog/sitemap-index.xml
`.trim();

export const GET: APIRoute = () => {
	return new Response(robotsTxt, {
		headers: {
			"Content-Type": "text/plain; charset=utf-8",
		},
	});
};
