export interface CredentialView {
	type: string;
	value?: string;
	ref?: string;
	redacted: boolean;
}

export interface EnvVar {
	key: string;
	value: string;
}

export interface GeneratedIdentity {
	identity: string;
	recipient: string;
}

export function validateSecretsJson(inputJson: string): void;
export function generateIdentityJson(): string;
export function listKeys(inputJson: string, project?: string): string[];
export function getCredentialJson(
	inputJson: string,
	project: string | undefined,
	key: string,
	reveal?: boolean,
): string;
export function exportEnvJson(
	inputJson: string,
	project?: string,
	prefix?: string,
	includeRefs?: boolean,
): string;
export function encryptBundle(
	inputJsonPath: string,
	outputCipherPath: string,
	recipientsJson: string,
): void;
export function decryptBundle(
	inputCipherPath: string,
	outputJsonPath: string,
	identityFilePath: string,
): void;
