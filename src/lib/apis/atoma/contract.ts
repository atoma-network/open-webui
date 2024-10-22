import { SuiClient, type SuiTransactionBlockResponse } from '@mysten/sui/client';
import { Transaction } from '@mysten/sui/transactions';
import { getZkAddress, getZkSignature } from './zklogin';

const SUI_ATOMA_PACKAGE = import.meta.env.VITE_SUI_ATOMA_PACKAGE;
const SUI_ATOMA_DB_PACKAGE = import.meta.env.VITE_SUI_ATOMA_DB_PACKAGE;
const SUI_RPC_URL = import.meta.env.VITE_SUI_RPC_URL;
const SUI_TOMA_PACKAGE = import.meta.env.VITE_SUI_TOMA_PACKAGE;
const SUI_TOMA_FAUCET = import.meta.env.VITE_SUI_TOMA_FAUCET;
const client = new SuiClient({ url: SUI_RPC_URL });

export const sponsorTransaction = async (
	token: string = '',
	tx: Transaction,
	sender: string,
	url: string
): Promise<Response | null> => {
	const uint8Array = await tx.build({ client, onlyTransactionKind: true });

	// Convert the Uint8Array to a binary string
	let binaryString = '';
	for (let i = 0; i < uint8Array.length; i++) {
		binaryString += String.fromCharCode(uint8Array[i]);
	}

	// Encode the binary string to Base64 and make it URL-safe
	const base64Encoded = btoa(binaryString)
		.replace(/\+/g, '-') // Replace + with -
		.replace(/\//g, '_') // Replace / with _
		.replace(/=+$/, ''); // Remove padding =

	let error = null;

	const res = await fetch(`${url}/sponsor/${base64Encoded}/${sender}`, {
		method: 'GET',
		headers: {
			Authorization: `Bearer ${token}`
		}
	}).catch((err) => {
		console.log(err);
		error = err;
		return null;
	});

	if (error) {
		throw error;
	}

	return res;
};

export const getFaucet = async (
	token: string = '',
	url: string
): Promise<SuiTransactionBlockResponse> => {
	const tx = new Transaction();
	tx.moveCall({
		target: `${SUI_TOMA_PACKAGE}::toma::faucet`,
		arguments: [tx.object(SUI_TOMA_FAUCET), tx.pure.u64(10000000000)]
	});
	const sender = getZkAddress();
	tx.setSender(sender);

	const sponsored = await sponsorTransaction(token, tx, sender, url);
	if (!sponsored) {
		throw new Error('Failed to sponsor transaction');
	}
	const signed = await sponsored.json();
	if (!signed) {
		throw new Error('Failed to sign transaction');
	}
	const result = signed.result;

	const zkLoginSignature = await getZkSignature(result.txBytes);

	return await client.executeTransactionBlock({
		transactionBlock: result.txBytes,
		signature: [zkLoginSignature, result.signature]
	});
};
