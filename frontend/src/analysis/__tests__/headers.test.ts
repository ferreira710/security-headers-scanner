import { describe, expect, it } from "vitest";

import {
	effectiveSources,
	HeaderBag,
	parseCsp,
	parseHsts,
	parsePermissionsPolicy,
	parseTokenList,
} from "../headers";
import { headers } from "./helpers";

describe("HeaderBag", () => {
	it("looks headers up case-insensitively", () => {
		const bag = new HeaderBag(headers({ "X-Frame-Options": "DENY" }));
		expect(bag.first("x-frame-options")).toBe("DENY");
		expect(bag.first("X-FRAME-OPTIONS")).toBe("DENY");
	});

	it("keeps duplicate headers separate instead of joining them", () => {
		const bag = new HeaderBag(
			headers({
				"content-security-policy": ["default-src 'self'", "img-src 'none'"],
			}),
		);
		expect(bag.all("content-security-policy")).toEqual([
			"default-src 'self'",
			"img-src 'none'",
		]);
	});

	it("reports absent headers as null, not undefined or empty string", () => {
		expect(new HeaderBag([]).first("x-frame-options")).toBeNull();
		expect(new HeaderBag([]).has("x-frame-options")).toBe(false);
	});
});

describe("parseCsp", () => {
	it("splits directives and lower-cases names", () => {
		const directives = parseCsp(
			"Default-Src 'self'; script-src 'self' https://cdn.example",
		);
		expect(directives.get("default-src")).toEqual(["'self'"]);
		expect(directives.get("script-src")).toEqual([
			"'self'",
			"https://cdn.example",
		]);
	});

	it("tolerates trailing semicolons and extra whitespace", () => {
		const directives = parseCsp("  default-src   'none' ;; base-uri 'self' ; ");
		expect(directives.get("default-src")).toEqual(["'none'"]);
		expect(directives.get("base-uri")).toEqual(["'self'"]);
	});

	it("keeps a value-less directive as an empty list, not as absent", () => {
		const directives = parseCsp("upgrade-insecure-requests");
		expect(directives.has("upgrade-insecure-requests")).toBe(true);
		expect(directives.get("upgrade-insecure-requests")).toEqual([]);
	});

	it("honours the first occurrence when a directive repeats, like the browser", () => {
		expect(
			parseCsp("script-src 'self'; script-src *").get("script-src"),
		).toEqual(["'self'"]);
	});
});

describe("effectiveSources", () => {
	it("falls back down the chain to default-src", () => {
		const directives = parseCsp("default-src 'self'");
		expect(effectiveSources(directives, ["script-src", "default-src"])).toEqual(
			["'self'"],
		);
	});

	it("prefers the more specific directive", () => {
		const directives = parseCsp("default-src 'none'; script-src 'self'");
		expect(effectiveSources(directives, ["script-src", "default-src"])).toEqual(
			["'self'"],
		);
	});

	it("returns null when nothing in the chain is set", () => {
		expect(
			effectiveSources(parseCsp("img-src 'self'"), [
				"script-src",
				"default-src",
			]),
		).toBeNull();
	});
});

describe("parseHsts", () => {
	it("reads max-age and flags regardless of case or spacing", () => {
		expect(parseHsts("max-age=31536000 ; IncludeSubDomains; Preload")).toEqual({
			maxAge: 31536000,
			includeSubDomains: true,
			preload: true,
		});
	});

	it("accepts the quoted max-age form allowed by RFC 6797", () => {
		expect(parseHsts('max-age="15768000"').maxAge).toBe(15768000);
	});

	it("reports a missing or unparseable max-age as null", () => {
		expect(parseHsts("includeSubDomains").maxAge).toBeNull();
		expect(parseHsts("max-age=forever").maxAge).toBeNull();
	});
});

describe("parsePermissionsPolicy", () => {
	it("splits features on commas outside the allowlist parentheses", () => {
		const features = parsePermissionsPolicy(
			'camera=(), geolocation=(self "https://a.example"), usb=()',
		);
		expect(features.get("camera")).toBe("()");
		expect(features.get("geolocation")).toBe('(self "https://a.example")');
		expect(features.get("usb")).toBe("()");
	});

	it("ignores segments without an allowlist", () => {
		expect(parsePermissionsPolicy("camera").size).toBe(0);
	});
});

describe("parseTokenList", () => {
	it("flattens repeated headers into one lower-cased token list", () => {
		expect(
			parseTokenList(["no-referrer, strict-origin", " UNSAFE-URL "]),
		).toEqual(["no-referrer", "strict-origin", "unsafe-url"]);
	});
});
