"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { execFileSync } = require("node:child_process");

const rootDir = path.resolve(__dirname, "..");
const manifestPath = path.join(rootDir, "native", "Cargo.toml");

execFileSync("cargo", ["build", "--release", "--manifest-path", manifestPath], {
	stdio: "inherit",
	cwd: rootDir,
});

const targetDir = path.join(rootDir, "native", "target", "release");
let libName;
if (process.platform === "darwin") {
	libName = "libseclusor_ts_napi.dylib";
} else if (process.platform === "linux") {
	libName = "libseclusor_ts_napi.so";
} else if (process.platform === "win32") {
	libName = "seclusor_ts_napi.dll";
} else {
	throw new Error(`Unsupported platform: ${process.platform}`);
}

const source = path.join(targetDir, libName);
if (!fs.existsSync(source)) {
	throw new Error(`Expected native artifact not found: ${source}`);
}

const outPrimary = path.join(
	rootDir,
	"native",
	`seclusor.${process.platform}-${process.arch}.node`,
);
const outFallback = path.join(rootDir, "native", "seclusor.node");
fs.copyFileSync(source, outPrimary);
fs.copyFileSync(source, outFallback);

console.log(`Native addon written: ${outPrimary}`);
