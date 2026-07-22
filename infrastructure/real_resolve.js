// This is a Node.js script dedicated to resolving DIDs using the official library.

const { Resolver } = require('did-resolver');
const { getResolver } = require('ethr-did-resolver');

// 1. Receive non-sensitive arguments from the command line.  Python passes the
// RPC URL through AGENTDID_RESOLVER_RPC_URL so provider tokens never appear in
// the process list.  The historical positional RPC argument remains supported
// for direct/manual use.
const args = process.argv.slice(2);
const did = args[0];
const envRpcUrl = process.env.AGENTDID_RESOLVER_RPC_URL;
const rpcUrl = envRpcUrl || args[1];
const configOffset = envRpcUrl ? 1 : 2;
const networkName = args[configOffset] || "sepolia";
const chainId = args[configOffset + 1] ? Number(args[configOffset + 1]) : 11155111;
const registry = args[configOffset + 2] || "0x03d5003bf0e79C5F5223588F347ebA39AfbC3818";

if (!did || !rpcUrl || !Number.isSafeInteger(chainId) || chainId <= 0) {
    console.error("Error: Please provide a DID and an RPC URL");
    process.exit(1);
}

async function run() {
    try {
        // 2. Configure connection
        const providerConfig = {
            networks: [
                {
                    name: networkName,
                    rpcUrl: rpcUrl,
                    chainId: chainId,
                    registry: registry
                }
            ]
        };

        // 3. Initialize the official resolver
        const ethrDidResolver = getResolver(providerConfig);
        const didResolver = new Resolver(ethrDidResolver);

        // 4. Execute resolution (fetches data from the chain)
        const doc = await didResolver.resolve(did);

        // 5. Print the result as a JSON string (Python will capture this output)
        console.log(JSON.stringify(doc, null, 4));

    } catch (error) {
        console.error("Error during resolution:", error);
        process.exit(1);
    }
}

run();
