"use strict";

const assert = require("node:assert/strict");
const os = require("node:os");
const path = require("node:path");
const fs = require("node:fs");

const seclusor = require("..");

const SAMPLE = JSON.stringify({
	schema_version: "v1.0.0",
	projects: [
		{
			project_slug: "demo",
			credentials: {
				API_KEY: {
					type: "secret",
					value: "sk-123",
				},
				REF_ONLY: {
					type: "ref",
					ref: "vault://demo/path",
				},
			},
		},
	],
});

seclusor.validateSecretsJson(SAMPLE);

const keys = seclusor.listKeys(SAMPLE, "demo");
assert.deepEqual(keys, ["API_KEY", "REF_ONLY"]);

const got = JSON.parse(
	seclusor.getCredentialJson(SAMPLE, "demo", "API_KEY", false),
);
assert.equal(got.type, "secret");
assert.equal(got.redacted, true);
assert.equal(got.value, "<redacted>");

const gotRef = JSON.parse(
	seclusor.getCredentialJson(SAMPLE, "demo", "REF_ONLY", false),
);
assert.equal(gotRef.redacted, true);
assert.equal(gotRef.ref, "<redacted>");

const env = JSON.parse(seclusor.exportEnvJson(SAMPLE, "demo", "APP_", true));
assert.equal(env.length, 2);
assert.equal(env[0].key, "APP_API_KEY");
assert.equal(env[0].value, "sk-123");

// bundle encrypt/decrypt roundtrip through file APIs
const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "seclusor-ts-"));
const inputJsonPath = path.join(tempDir, "secrets.json");
const bundlePath = path.join(tempDir, "secrets.age");
const outputJsonPath = path.join(tempDir, "out.json");
const identityPath = path.join(tempDir, "identity.txt");

fs.writeFileSync(inputJsonPath, SAMPLE, "utf8");
const generated = JSON.parse(seclusor.generateIdentityJson());
fs.writeFileSync(identityPath, `${generated.identity}\n`, { mode: 0o600 });

seclusor.encryptBundle(
	inputJsonPath,
	bundlePath,
	JSON.stringify([generated.recipient]),
);
seclusor.decryptBundle(bundlePath, outputJsonPath, identityPath);

const outputJson = fs.readFileSync(outputJsonPath, "utf8");
const parsed = JSON.parse(outputJson);
assert.equal(parsed.projects[0].project_slug, "demo");

const oversizedPath = path.join(tempDir, "oversized.json");
const oversized = `{"schema_version":"v1.0.0","projects":[{"project_slug":"x","credentials":{"K":{"type":"secret","value":"${"a".repeat(2_200_000)}"}}}]}`;
fs.writeFileSync(oversizedPath, oversized, "utf8");
assert.throws(
	() => seclusor.validateSecretsJson(oversized),
	/document exceeds maximum size/,
);
assert.throws(
	() => seclusor.listKeys(oversized, "x"),
	/document exceeds maximum size/,
);
assert.throws(
	() =>
		seclusor.encryptBundle(
			oversizedPath,
			bundlePath,
			JSON.stringify([generated.recipient]),
		),
	/document exceeds maximum size/,
);

const malformed = `{"schema_version":"v1.0.0","projects":"cfat_secret_token"}`;
assert.throws(
	() => seclusor.validateSecretsJson(malformed),
	(error) => {
		assert.match(error.message, /string "<redacted>"/);
		assert.doesNotMatch(error.message, /cfat_secret_token/);
		return true;
	},
);

console.log("TypeScript binding integration tests passed");
