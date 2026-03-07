"use strict";

const fs = require("node:fs");
const path = require("node:path");

function resolveBindingPath() {
	const platform = process.platform;
	const arch = process.arch;
	const candidates = [
		path.join(__dirname, "native", `seclusor.${platform}-${arch}.node`),
		path.join(__dirname, "native", "seclusor.node"),
	];

	for (const candidate of candidates) {
		if (fs.existsSync(candidate)) {
			return candidate;
		}
	}

	throw new Error(
		`No seclusor native binding found for ${platform}-${arch}. Run \"npm run build\" first.`,
	);
}

module.exports = require(resolveBindingPath());
