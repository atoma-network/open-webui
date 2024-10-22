import { SuiClient } from '@mysten/sui/client';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import {
	genAddressSeed,
	generateNonce,
	generateRandomness,
	getExtendedEphemeralPublicKey,
	getZkLoginSignature,
	jwtToAddress
} from '@mysten/zklogin';
import { jwtDecode } from 'jwt-decode';

const LOCAL_STORAGE_SALT = 'ZKLOGIN-SALT';
const LOCAL_STORAGE_SECRET_KEY = 'ZKLOGIN-SECRET_KEY';
const LOCAL_STORAGE_RANDOMNESS = 'ZKLOGIN-RANDOMNESS';
const LOCAL_STORAGE_MAX_EPOCH = 'ZKLOGIN-MAX_EPOCH';
const LOCAL_STORAGE_ZK_ADDRESS = 'ZKLOGIN-ZK_ADDRESS';
const LOCAL_STORAGE_ID_TOKEN = 'ZKLOGIN-ID_TOKEN';
const LOCAL_STORAGE_ZKP = 'ZKLOGIN-ZKP';
const SUI_RPC_URL = import.meta.env.VITE_SUI_RPC_URL;
const PROVER_URL = import.meta.env.VITE_PROVER_URL;

const suiClient = new SuiClient({ url: SUI_RPC_URL });

type PartialZkLoginSignature = Omit<
	Parameters<typeof getZkLoginSignature>['0']['inputs'],
	'addressSeed'
>;

export async function prepare(): Promise<string> {
	if (localStorage.getItem(LOCAL_STORAGE_ID_TOKEN)) {
		// Already have id token. No need to generate nonce.
		return '';
	}
	const ephemeralKeyPair = new Ed25519Keypair();
	localStorage.setItem(LOCAL_STORAGE_SECRET_KEY, ephemeralKeyPair.getSecretKey());
	const { epoch } = await suiClient.getLatestSuiSystemState();
	const maxEpoch = Number(epoch) + 2;
	localStorage.setItem(LOCAL_STORAGE_MAX_EPOCH, maxEpoch.toString());
	const randomness = generateRandomness();
	localStorage.setItem(LOCAL_STORAGE_RANDOMNESS, randomness);
	const nonce = generateNonce(ephemeralKeyPair.getPublicKey(), maxEpoch, randomness);
	return nonce;
}

export async function receiveToken(idToken: string) {
	// const encodedJWT = urlParams.get('id_token');
	// const address = jwtToAddress(idToken);
	localStorage.setItem(LOCAL_STORAGE_ID_TOKEN, idToken);
	const maxEpoch = localStorage.getItem(LOCAL_STORAGE_MAX_EPOCH);
	const secret_key = localStorage.getItem(LOCAL_STORAGE_SECRET_KEY);
	// TODO: We should store the salt in the DB. Or use some salt server (sui provides this). If user lose the salt, they will need a new one which will result in a new address.
	let salt = localStorage.getItem(LOCAL_STORAGE_SALT);
	const randomness = localStorage.getItem(LOCAL_STORAGE_RANDOMNESS);
	let zkLoginUserAddress = localStorage.getItem(LOCAL_STORAGE_ZK_ADDRESS);

	if (!salt) {
		// Generate new salt if this is first time.
		const saltArray = crypto.getRandomValues(new Uint8Array(16));
		salt = BigInt(
			'0x' +
				Array.from(saltArray)
					.map((b) => b.toString(16).padStart(2, '0'))
					.join('')
		).toString();
		localStorage.setItem(LOCAL_STORAGE_SALT, salt);
	}
	zkLoginUserAddress = jwtToAddress(idToken, salt);
	localStorage.setItem(LOCAL_STORAGE_ZK_ADDRESS, zkLoginUserAddress);
	let ephemeralKeyPair;
	if (secret_key) {
		ephemeralKeyPair = Ed25519Keypair.fromSecretKey(secret_key);
	} else {
		ephemeralKeyPair = new Ed25519Keypair();
		localStorage.setItem(LOCAL_STORAGE_SECRET_KEY, ephemeralKeyPair.getSecretKey());
	}

	const extendedEphemeralPublicKey = getExtendedEphemeralPublicKey(ephemeralKeyPair.getPublicKey());
	console.log('extendedEphemeralPublicKey', extendedEphemeralPublicKey);
	const response = await fetch(PROVER_URL, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json'
		},
		body: JSON.stringify({
			jwt: idToken,
			extendedEphemeralPublicKey,
			maxEpoch: maxEpoch,
			jwtRandomness: randomness,
			salt,
			keyClaimName: 'sub'
		})
	});
	const zkProofResult = await response.json();
	const partialLogin = zkProofResult as PartialZkLoginSignature;
	localStorage.setItem(LOCAL_STORAGE_ZKP, JSON.stringify(partialLogin));
	console.log('partialLogin', partialLogin);
}

export function getZkAddress() {
	const address = localStorage.getItem(LOCAL_STORAGE_ZK_ADDRESS);
	if (!address) {
		throw new Error('No address found');
	}
	return address;
}

function base64ToUint8Array(base64: string): Uint8Array {
	// Decode the base64 string to a binary string
	const binaryString = atob(base64);

	// Create a Uint8Array to hold the decoded data
	const length = binaryString.length;
	const uint8Array = new Uint8Array(length);

	// Fill the Uint8Array with the binary string data
	for (let i = 0; i < length; i++) {
		uint8Array[i] = binaryString.charCodeAt(i);
	}

	return uint8Array;
}

export async function getZkSignature(transaction: string) {
	const idToken = localStorage.getItem(LOCAL_STORAGE_ID_TOKEN);
	if (!idToken) {
		throw new Error('No id token found');
	}
	const jwtPayload = jwtDecode(idToken);
	if (jwtPayload?.sub === undefined || jwtPayload?.aud === undefined) {
		throw new Error('Invalid jwt payload');
	}
	let aud;
	if (typeof jwtPayload.aud === 'string') {
		aud = jwtPayload.aud;
	} else {
		aud = jwtPayload.aud[0];
	}
	const salt = localStorage.getItem(LOCAL_STORAGE_SALT);
	if (!salt) {
		throw new Error('No salt found');
	}
	const addressSeed: string = genAddressSeed(BigInt(salt), 'sub', jwtPayload.sub, aud).toString();

	const partialZkLoginSignatureJson = localStorage.getItem(LOCAL_STORAGE_ZKP);
	if (!partialZkLoginSignatureJson) {
		throw new Error('No partial zk login signature found');
	}
	const partialZkLoginSignature: PartialZkLoginSignature = JSON.parse(partialZkLoginSignatureJson);

	const maxEpoch = localStorage.getItem(LOCAL_STORAGE_MAX_EPOCH);
	if (!maxEpoch) {
		throw new Error('No max epoch found');
	}

	const secretKey = localStorage.getItem(LOCAL_STORAGE_SECRET_KEY);
	if (!secretKey) {
		throw new Error('No secret key found');
	}
	const keypair = Ed25519Keypair.fromSecretKey(secretKey);

	const { signature: userSignature } = await keypair.signTransaction(
		base64ToUint8Array(transaction)
	);

	const zkLoginSignature = getZkLoginSignature({
		inputs: {
			...partialZkLoginSignature,
			addressSeed
		},
		maxEpoch,
		userSignature
	});

	return zkLoginSignature;
}
